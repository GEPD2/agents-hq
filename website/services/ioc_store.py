import hashlib
import os
from datetime import datetime

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


def ingest_report(filename: str) -> int:
    from services.report_parser import extract_iocs, read_report, get_agent_type
    content = read_report(filename)
    if not content:
        return 0

    iocs_raw = extract_iocs(content)
    agent_id = get_agent_type(filename)
    seen_at  = datetime.utcnow()

    pairs = []
    for itype, values in [
        ("ip",     iocs_raw.get("ips", [])),
        ("cve",    iocs_raw.get("cves", [])),
        ("onion",  iocs_raw.get("onions", [])),
        ("wallet", iocs_raw.get("wallets", [])),
        ("hash",   iocs_raw.get("hashes", [])),
        ("domain", iocs_raw.get("domains", [])),
    ]:
        for v in values:
            pairs.append((itype, str(v)[:500]))

    if not pairs:
        return 0

    try:
        with _conn() as db:
            with db.cursor() as cur:
                for itype, value in pairs:
                    ioc_id = hashlib.md5(f"{itype}::{value}::{filename}".encode()).hexdigest()
                    cur.execute("""
                        INSERT IGNORE INTO iocs (id, type, value, report_file, agent_id, seen_at)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (ioc_id, itype, value, filename, agent_id, seen_at))
            db.commit()
        return len(pairs)
    except Exception:
        return 0


def ingest_all() -> dict:
    from services.report_parser import list_reports
    reports = list_reports()
    total = 0
    for r in reports:
        total += ingest_report(r["filename"])
    return {"reports": len(reports), "iocs": total}


def list_iocs(itype: str = None, page: int = 1, per_page: int = 60) -> list:
    try:
        offset = (page - 1) * per_page
        with _conn() as db:
            with db.cursor() as cur:
                if itype:
                    cur.execute("""
                        SELECT type, value,
                               COUNT(*) AS report_count,
                               MIN(seen_at) AS first_seen,
                               MAX(seen_at) AS last_seen
                        FROM iocs WHERE type=%s
                        GROUP BY type, value
                        ORDER BY report_count DESC, last_seen DESC
                        LIMIT %s OFFSET %s
                    """, (itype, per_page, offset))
                else:
                    cur.execute("""
                        SELECT type, value,
                               COUNT(*) AS report_count,
                               MIN(seen_at) AS first_seen,
                               MAX(seen_at) AS last_seen
                        FROM iocs
                        GROUP BY type, value
                        ORDER BY report_count DESC, last_seen DESC
                        LIMIT %s OFFSET %s
                    """, (per_page, offset))
                rows = cur.fetchall()
        for r in rows:
            r["first_seen"] = str(r["first_seen"]) if r.get("first_seen") else ""
            r["last_seen"]  = str(r["last_seen"])  if r.get("last_seen")  else ""
        return rows
    except Exception:
        return []


def get_ioc_detail(itype: str, value: str) -> dict | None:
    try:
        with _conn() as db:
            with db.cursor() as cur:
                cur.execute("""
                    SELECT report_file, agent_id, seen_at
                    FROM iocs WHERE type=%s AND value=%s
                    ORDER BY seen_at DESC
                """, (itype, value))
                rows = cur.fetchall()
        if not rows:
            return None
        for r in rows:
            r["seen_at"] = str(r["seen_at"]) if r.get("seen_at") else ""
        return {"type": itype, "value": value, "reports": rows, "count": len(rows)}
    except Exception:
        return None


def correlate_ioc(itype: str, value: str) -> list:
    try:
        with _conn() as db:
            with db.cursor() as cur:
                cur.execute(
                    "SELECT report_file FROM iocs WHERE type=%s AND value=%s",
                    (itype, value),
                )
                files = [r["report_file"] for r in cur.fetchall()]
                if not files:
                    return []
                placeholders = ",".join(["%s"] * len(files))
                cur.execute(f"""
                    SELECT type, value,
                           COUNT(*) AS co_count,
                           GROUP_CONCAT(DISTINCT report_file ORDER BY report_file SEPARATOR '|||') AS in_reports
                    FROM iocs
                    WHERE report_file IN ({placeholders})
                      AND NOT (type=%s AND value=%s)
                    GROUP BY type, value
                    ORDER BY co_count DESC
                    LIMIT 100
                """, (*files, itype, value))
                rows = cur.fetchall()
        for r in rows:
            r["in_reports"] = r["in_reports"].split("|||") if r.get("in_reports") else []
        return rows
    except Exception:
        return []


def get_stats() -> list:
    try:
        with _conn() as db:
            with db.cursor() as cur:
                cur.execute("""
                    SELECT type,
                           COUNT(DISTINCT value) AS unique_count,
                           COUNT(*) AS total_occurrences
                    FROM iocs
                    GROUP BY type
                    ORDER BY unique_count DESC
                """)
                return cur.fetchall()
    except Exception:
        return []
