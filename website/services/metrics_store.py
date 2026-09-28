"""KPI time-series for the dashboard tiles.

Records one daily snapshot of the platform counts in metrics_snapshots and serves
the recent series with a delta per tile. Reports and CRITICAL come from the
filesystem (report_parser); kb_docs / threat_actors / iocs from MySQL. Falls back
to filesystem-only figures when MySQL is unavailable so the tiles still populate.
"""

from datetime import date, datetime

from services import mysql_client
from services.report_parser import list_reports

_TILES = ["reports", "kb_docs", "threat_actors", "critical"]


def _fs_counts() -> dict:
    reports = list_reports()
    critical = sum((r.get("priority_counts") or {}).get("CRITICAL", 0) for r in reports)
    return {"reports": len(reports), "critical": critical}


def _current_counts() -> dict:
    counts = {"reports": 0, "kb_docs": 0, "threat_actors": 0, "iocs": 0, "critical": 0}
    counts.update(_fs_counts())
    if mysql_client.is_available():
        try:
            with mysql_client._conn() as db:
                with db.cursor() as cur:
                    cur.execute("SELECT COUNT(*) AS n FROM documents")
                    counts["kb_docs"] = cur.fetchone()["n"]
                    cur.execute("SELECT COUNT(*) AS n FROM threat_actors")
                    counts["threat_actors"] = cur.fetchone()["n"]
                    cur.execute("SELECT COUNT(*) AS n FROM iocs")
                    counts["iocs"] = cur.fetchone()["n"]
        except Exception:
            pass
    return counts


def snapshot_today() -> None:
    if not mysql_client.is_available():
        return
    c = _current_counts()
    try:
        with mysql_client._conn() as db:
            with db.cursor() as cur:
                cur.execute(
                    "INSERT INTO metrics_snapshots"
                    " (snap_date, reports, kb_docs, threat_actors, iocs, critical, taken_at)"
                    " VALUES (%s,%s,%s,%s,%s,%s,%s)"
                    " ON DUPLICATE KEY UPDATE reports=VALUES(reports), kb_docs=VALUES(kb_docs),"
                    " threat_actors=VALUES(threat_actors), iocs=VALUES(iocs),"
                    " critical=VALUES(critical), taken_at=VALUES(taken_at)",
                    (date.today(), c["reports"], c["kb_docs"], c["threat_actors"],
                     c["iocs"], c["critical"], datetime.utcnow()),
                )
            db.commit()
    except Exception:
        pass


def get_metrics(days: int = 30) -> dict:
    snapshot_today()
    current = _current_counts()

    rows: list[dict] = []
    if mysql_client.is_available():
        try:
            with mysql_client._conn() as db:
                with db.cursor() as cur:
                    cur.execute(
                        "SELECT snap_date, reports, kb_docs, threat_actors, iocs, critical"
                        " FROM metrics_snapshots ORDER BY snap_date DESC LIMIT %s",
                        (days,),
                    )
                    rows = list(cur.fetchall())[::-1]  # oldest first
        except Exception:
            rows = []

    tiles = {}
    for key in _TILES:
        series = [int(r[key]) for r in rows] if rows else [current[key]]
        # Delta = latest recorded vs the prior snapshot (0 when only one point).
        delta = (series[-1] - series[-2]) if len(series) >= 2 else 0
        tiles[key] = {"value": current[key], "delta": delta, "series": series}

    return {"tiles": tiles, "points": len(rows)}
