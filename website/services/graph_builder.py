import os
from collections import defaultdict
from datetime import datetime, timedelta
from itertools import combinations

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

MAX_NODES = 300
MAX_IOCS_PER_REPORT = 40   # cap co-occurrence expansion per report
MAX_EDGES = 1500


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


def _fetch_iocs(itype: str | None, agent: str | None, days: int | None) -> list[dict]:
    clauses, params = [], []
    if itype:
        clauses.append("type=%s"); params.append(itype)
    if agent:
        clauses.append("agent_id=%s"); params.append(agent)
    if days:
        clauses.append("seen_at >= %s"); params.append(datetime.utcnow() - timedelta(days=days))
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    try:
        with _conn() as db:
            with db.cursor() as cur:
                cur.execute(
                    f"SELECT type, value, report_file, agent_id, seen_at FROM iocs {where} LIMIT 20000",
                    params,
                )
                return cur.fetchall()
    except Exception:
        return []


def _fetch_threat_actors() -> list[dict]:
    try:
        with _conn() as db:
            with db.cursor() as cur:
                cur.execute("SELECT id, name, content FROM threat_actors")
                return cur.fetchall()
    except Exception:
        return []


def build_graph(itype: str | None = None, agent: str | None = None, days: int | None = None) -> dict:
    rows = _fetch_iocs(itype, agent, days)

    # node_id -> aggregate
    node_count: dict[str, int] = defaultdict(int)
    node_meta: dict[str, dict] = {}
    report_iocs: dict[str, set] = defaultdict(set)

    for r in rows:
        nid = f"{r['type']}:{r['value']}"
        node_count[nid] += 1
        if nid not in node_meta:
            node_meta[nid] = {"type": r["type"], "value": r["value"], "agent": r.get("agent_id")}
        report_iocs[r["report_file"]].add(nid)

    # keep the top-N nodes by frequency to stay renderable
    top = sorted(node_count.items(), key=lambda kv: kv[1], reverse=True)[:MAX_NODES]
    keep = {nid for nid, _ in top}

    nodes = []
    for nid in keep:
        m = node_meta[nid]
        nodes.append({
            "data": {
                "id": nid,
                "label": m["value"][:40],
                "ntype": m["type"],
                "agent": m["agent"],
                "count": node_count[nid],
            }
        })

    # co-occurrence edges within each report, restricted to kept nodes
    edge_weight: dict[tuple, int] = defaultdict(int)
    for members in report_iocs.values():
        members = [m for m in members if m in keep]
        if len(members) < 2:
            continue
        members = members[:MAX_IOCS_PER_REPORT]
        for a, b in combinations(sorted(members), 2):
            edge_weight[(a, b)] += 1

    edges = []
    for (a, b), w in sorted(edge_weight.items(), key=lambda kv: kv[1], reverse=True)[:MAX_EDGES]:
        edges.append({"data": {"id": f"{a}__{b}", "source": a, "target": b, "weight": w, "etype": "cooccur"}})

    # threat actor nodes linked by substring match against kept IOC values
    for ta in _fetch_threat_actors():
        content = (ta.get("content") or "") + " " + (ta.get("name") or "")
        linked = []
        for nid in keep:
            val = node_meta[nid]["value"]
            if len(val) >= 6 and val in content:
                linked.append(nid)
        if not linked:
            continue
        ta_id = f"actor:{ta['id']}"
        nodes.append({"data": {"id": ta_id, "label": ta["name"][:40], "ntype": "actor",
                               "agent": "10", "count": len(linked)}})
        for nid in linked[:50]:
            edges.append({"data": {"id": f"{ta_id}__{nid}", "source": ta_id, "target": nid,
                                   "weight": 1, "etype": "actor"}})

    return {
        "nodes": nodes,
        "edges": edges,
        "truncated": len(node_count) > MAX_NODES,
        "total_nodes": len(node_count),
    }
