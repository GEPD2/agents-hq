"""Rolling "recent findings" feed for the dashboard live stream.

A finding is one of:
  - an IOC row from the MySQL iocs table (type, value, agent, report)
  - a report file appearing in REPORTS_DIR, carrying its top severity

recent_findings() serves the initial paint and the non-SSE fallback.
stream_findings() is an SSE generator: it primes silently on connect, then
polls on an interval and emits only findings it has not sent yet. Both degrade
to filesystem-only findings when MySQL is unavailable.
"""

import asyncio
import json
import os
from datetime import datetime, timezone

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

POLL_INTERVAL = float(os.environ.get("FINDINGS_POLL_INTERVAL", "3"))
HEARTBEAT_AFTER = 20.0
_SEEN_CAP = 2000


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


def _ts(value) -> str:
    """Normalize to a UTC-aware ISO string. The iocs table stores seen_at as a
    naive UTC datetime (datetime.utcnow), so it is tagged UTC here. Reports use
    the same UTC basis (see _recent_reports) so both sources sort consistently,
    and a tz-aware string still renders as correct local time in the browser."""
    if hasattr(value, "isoformat"):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value or "")


def _recent_iocs(limit: int) -> list[dict]:
    try:
        with _conn() as db:
            with db.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, type, value, report_file, agent_id, seen_at
                    FROM iocs
                    ORDER BY seen_at DESC, id DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                rows = cur.fetchall()
    except Exception:
        return []

    out = []
    for r in rows:
        out.append({
            "id": "ioc:" + str(r.get("id")),
            "kind": "ioc",
            "ioc_type": r.get("type") or "",
            "value": r.get("value") or "",
            "agent": r.get("agent_id") or "unknown",
            "report_file": r.get("report_file") or "",
            "severity": "",
            "ts": _ts(r.get("seen_at")),
        })
    return out


def _recent_reports(limit: int) -> list[dict]:
    from services.report_parser import list_reports, REPORTS_DIR

    out = []
    for r in list_reports()[:limit]:
        counts = r.get("priority_counts") or {}
        if counts.get("CRITICAL"):
            severity = "critical"
        elif counts.get("HIGH"):
            severity = "high"
        else:
            severity = ""
        # Derive the timestamp as UTC from the file mtime so it shares a basis
        # with the iocs seen_at (which is UTC); list_reports' 'created' is local.
        try:
            mtime = (REPORTS_DIR / r["filename"]).stat().st_mtime
            ts = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
        except Exception:
            ts = ""
        out.append({
            "id": "report:" + r["filename"],
            "kind": "report",
            "ioc_type": "",
            "value": r["filename"],
            "agent": r.get("agent") or "unknown",
            "report_file": r["filename"],
            "severity": severity,
            "ts": ts,
        })
    return out


def recent_findings(limit: int = 30) -> list[dict]:
    """Merge recent IOCs and reports, newest first. Blocking (DB + filesystem);
    call from a thread when on the event loop."""
    items = _recent_iocs(limit) + _recent_reports(limit)
    items.sort(key=lambda x: x.get("ts") or "", reverse=True)
    return items[:limit]


async def stream_findings():
    """Yield SSE frames for findings as they appear. Emits full 'data: ...\\n\\n'
    frames like the other streamers, plus [READY] and periodic [HEARTBEAT]."""
    loop = asyncio.get_event_loop()
    seen: set[str] = set()

    try:
        primed = await loop.run_in_executor(None, recent_findings, 60)
        seen.update(f["id"] for f in primed)
    except Exception:
        pass
    yield "data: [READY]\n\n"

    idle = 0.0
    while True:
        try:
            batch = await loop.run_in_executor(None, recent_findings, 40)
        except Exception:
            batch = []

        fresh = [f for f in batch if f["id"] not in seen]
        # batch is newest-first; emit oldest-first so a client that prepends
        # each frame ends with the newest finding on top.
        for f in reversed(fresh):
            seen.add(f["id"])
            yield f"data: {json.dumps(f)}\n\n"

        if fresh:
            idle = 0.0
        else:
            idle += POLL_INTERVAL
            if idle >= HEARTBEAT_AFTER:
                idle = 0.0
                yield "data: [HEARTBEAT]\n\n"

        if len(seen) > _SEEN_CAP:
            seen = set(list(seen)[-(_SEEN_CAP // 2):])

        await asyncio.sleep(POLL_INTERVAL)
