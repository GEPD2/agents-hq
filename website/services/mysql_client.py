import os
import json
import uuid
from datetime import datetime
from typing import Optional

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


def is_available() -> bool:
    if not HAS_PYMYSQL:
        return False
    try:
        with _conn() as c:
            with c.cursor() as cur:
                cur.execute("SELECT 1")
        return True
    except Exception:
        return False


def list_collections() -> list[dict]:
    try:
        with _conn() as c:
            with c.cursor() as cur:
                cur.execute("""
                    SELECT collection AS name, COUNT(*) AS count
                    FROM documents
                    GROUP BY collection
                    ORDER BY collection
                """)
                rows = cur.fetchall()
        return [{"name": r["name"], "id": r["name"], "count": r["count"]} for r in rows]
    except Exception:
        return []


def get_total_documents() -> int:
    try:
        with _conn() as c:
            with c.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS n FROM documents")
                return cur.fetchone()["n"]
    except Exception:
        return 0


def search(query: str, collection: str = "security_docs", n_results: int = 10) -> list[dict]:
    try:
        with _conn() as c:
            with c.cursor() as cur:
                cur.execute("""
                    SELECT id, collection, content, source, doc_timestamp, metadata,
                           MATCH(content) AGAINST (%s IN BOOLEAN MODE) AS score
                    FROM documents
                    WHERE MATCH(content) AGAINST (%s IN BOOLEAN MODE)
                    ORDER BY score DESC
                    LIMIT %s
                """, (query, query, n_results))
                rows = cur.fetchall()
        return [_row_to_doc(r) for r in rows]
    except Exception:
        return []


def list_documents(collection_name: str, offset: int = 0, limit: int = 20) -> dict:
    try:
        with _conn() as c:
            with c.cursor() as cur:
                cur.execute(
                    "SELECT id, collection, content, source, doc_timestamp, metadata FROM documents WHERE collection=%s ORDER BY created_at DESC LIMIT %s OFFSET %s",
                    (collection_name, limit, offset),
                )
                rows = cur.fetchall()
                cur.execute("SELECT COUNT(*) AS n FROM documents WHERE collection=%s", (collection_name,))
                total = cur.fetchone()["n"]
        return {"documents": [_row_to_doc(r) for r in rows], "total": total}
    except Exception:
        return {"documents": [], "total": 0}


def get_threat_actors() -> list[dict]:
    try:
        with _conn() as c:
            with c.cursor() as cur:
                cur.execute("SELECT id, name, content, last_updated, metadata FROM threat_actors ORDER BY last_updated DESC")
                rows = cur.fetchall()
        return [_ta_to_dict(r) for r in rows]
    except Exception:
        return []


def upsert_document(doc_id: str, collection: str, content: str,
                    source: str = "", timestamp: Optional[datetime] = None,
                    metadata: Optional[dict] = None) -> None:
    with _conn() as c:
        with c.cursor() as cur:
            cur.execute("""
                INSERT INTO documents (id, collection, content, source, doc_timestamp, metadata)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    content=VALUES(content), source=VALUES(source),
                    doc_timestamp=VALUES(doc_timestamp), metadata=VALUES(metadata)
            """, (doc_id, collection, content, source, timestamp, json.dumps(metadata or {})))
        c.commit()


def upsert_threat_actor(name: str, content: str, metadata: Optional[dict] = None) -> None:
    actor_id = name.lower().replace(" ", "_")
    with _conn() as c:
        with c.cursor() as cur:
            cur.execute("""
                INSERT INTO threat_actors (id, name, content, last_updated, metadata)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    content=VALUES(content), last_updated=VALUES(last_updated),
                    metadata=VALUES(metadata)
            """, (actor_id, name, content, datetime.utcnow(), json.dumps(metadata or {})))
        c.commit()


def _row_to_doc(r: dict) -> dict:
    meta = r.get("metadata") or {}
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except Exception:
            meta = {}
    return {
        "id": r["id"],
        "content": r.get("content", ""),
        "metadata": meta,
        "source": r.get("source") or meta.get("source", "unknown"),
        "timestamp": str(r["doc_timestamp"]) if r.get("doc_timestamp") else "",
        "distance": r.get("score"),
    }


def _ta_to_dict(r: dict) -> dict:
    meta = r.get("metadata") or {}
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except Exception:
            meta = {}
    return {
        "id": r["id"],
        "name": r["name"],
        "content": r.get("content", ""),
        "metadata": meta,
        "last_updated": str(r["last_updated"]) if r.get("last_updated") else "",
    }
