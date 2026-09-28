"""
Shared MySQL-backed RAG module for all AGENTS-HQ agents.
Drop-in replacement for the ChromaDB RAG functions.

Usage in any agent:
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))
    from rag_mysql import rag_lookup, rag_ingest, rag_ingest_threat_actor
"""

import os
import json
import uuid
import re
from datetime import datetime

try:
    import pymysql
    import pymysql.cursors
    _HAS_PYMYSQL = True
except ImportError:
    _HAS_PYMYSQL = False

_HOST = os.environ.get("MYSQL_HOST", "localhost")
_PORT = int(os.environ.get("MYSQL_PORT", "3306"))
_DB   = os.environ.get("MYSQL_DATABASE", "agents_hq")
_USER = os.environ.get("MYSQL_USER", "agents")
_PASS = os.environ.get("MYSQL_PASSWORD", "agents_hq")


def _conn():
    return pymysql.connect(
        host=_HOST, port=_PORT,
        user=_USER, password=_PASS,
        database=_DB, charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=5,
    )


def rag_lookup(query: str, n_results: int = 3) -> str:
    """Keyword fulltext search across all documents. Returns formatted context or 'new intelligence'."""
    if not _HAS_PYMYSQL:
        return "[RAG_LOOKUP] Error: pymysql not installed"
    try:
        with _conn() as c:
            with c.cursor() as cur:
                cur.execute("""
                    SELECT content, source
                    FROM documents
                    WHERE MATCH(content) AGAINST (%s IN BOOLEAN MODE)
                    ORDER BY MATCH(content) AGAINST (%s IN BOOLEAN MODE) DESC
                    LIMIT %s
                """, (query, query, n_results))
                rows = cur.fetchall()
        if not rows:
            return "[RAG_LOOKUP] Not in knowledge base — new intelligence."
        snippets = [f"[{r['source']}]\n{r['content'][:600]}" for r in rows]
        return "[RAG_LOOKUP] Known context:\n" + "\n---\n".join(snippets)
    except Exception as e:
        return f"[RAG_LOOKUP] Error: {e}"


def rag_ingest(text: str, source: str, doc_id: str | None = None,
               collection: str = "security_docs") -> str:
    """Store text in MySQL documents table, chunked for fulltext search."""
    if not _HAS_PYMYSQL:
        return "[RAG_INGEST] Error: pymysql not installed"
    try:
        ts  = datetime.utcnow()
        uid = uuid.uuid4().hex[:8]
        chunks, start, i = [], 0, 0
        while start < len(text):
            chunk_id = doc_id or f"{source}_{ts.strftime('%Y%m%d_%H%M%S')}_{uid}_{i}"
            chunks.append((chunk_id, collection, text[start:start + 800], source, ts,
                           json.dumps({"source": source, "timestamp": ts.isoformat()})))
            start += 650
            i += 1
        with _conn() as c:
            with c.cursor() as cur:
                cur.executemany("""
                    INSERT INTO documents (id, collection, content, source, doc_timestamp, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        content=VALUES(content), doc_timestamp=VALUES(doc_timestamp)
                """, chunks)
            c.commit()
        return f"[RAG_INGEST] Stored {len(chunks)} chunk(s) from {source}"
    except Exception as e:
        return f"[RAG_INGEST] Error: {e}"


def rag_ingest_threat_actor(name: str, data: str) -> str:
    """Upsert a threat actor profile into the threat_actors table."""
    if not _HAS_PYMYSQL:
        return "[UPDATE_TA] Error: pymysql not installed"
    try:
        actor_id = "ta_" + re.sub(r'[^a-z0-9]', '_', name.lower().strip())
        ts = datetime.utcnow()
        content = f"# Threat Actor Profile: {name}\nLast updated: {ts.strftime('%Y-%m-%d %H:%M UTC')}\n\n{data.strip()}"
        with _conn() as c:
            with c.cursor() as cur:
                cur.execute("""
                    INSERT INTO threat_actors (id, name, content, last_updated, metadata)
                    VALUES (%s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        content=VALUES(content), last_updated=VALUES(last_updated)
                """, (actor_id, name, content, ts, json.dumps({"group_name": name})))
            c.commit()
        return f"[UPDATE_TA] Upserted profile for {name}"
    except Exception as e:
        return f"[UPDATE_TA] Error: {e}"
