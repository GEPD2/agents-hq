import os
import json
import urllib.request
import urllib.error
from typing import Optional

CHROMA_HOST = os.environ.get("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.environ.get("CHROMA_PORT", "8000"))
CHROMA_BASE = f"http://{CHROMA_HOST}:{CHROMA_PORT}/api/v2"


def _get(path: str, timeout: int = 10) -> dict | list:
    url = f"{CHROMA_BASE}{path}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _post(path: str, body: dict, timeout: int = 15) -> dict | list:
    url = f"{CHROMA_BASE}{path}"
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def list_collections() -> list[dict]:
    try:
        raw = _get("/collections")
        if isinstance(raw, list):
            return raw
        return raw.get("collections", [])
    except Exception:
        return []


def get_collection_count(collection_name: str) -> int:
    try:
        cols = list_collections()
        col = next((c for c in cols if c.get("name") == collection_name), None)
        if not col:
            return 0
        col_id = col.get("id", collection_name)
        result = _get(f"/collections/{col_id}/count")
        if isinstance(result, int):
            return result
        return result.get("count", 0)
    except Exception:
        return 0


def get_total_documents() -> int:
    try:
        cols = list_collections()
        total = 0
        for col in cols:
            col_id = col.get("id", col.get("name", ""))
            try:
                result = _get(f"/collections/{col_id}/count")
                if isinstance(result, int):
                    total += result
                else:
                    total += result.get("count", 0)
            except Exception:
                pass
        return total
    except Exception:
        return 0


def search(query: str, collection_name: str = "security_docs", n_results: int = 10) -> list[dict]:
    try:
        cols = list_collections()
        col = next((c for c in cols if c.get("name") == collection_name), None)
        if not col:
            if cols:
                col = cols[0]
            else:
                return []
        col_id = col.get("id", col.get("name", ""))
        result = _post(f"/collections/{col_id}/query", {
            "query_texts": [query],
            "n_results": n_results,
            "include": ["documents", "metadatas", "distances"],
        })
        docs = result.get("documents", [[]])[0]
        metas = result.get("metadatas", [[]])[0]
        distances = result.get("distances", [[]])[0]
        out = []
        for i, doc in enumerate(docs):
            m = metas[i] if i < len(metas) else {}
            d = distances[i] if i < len(distances) else None
            out.append({
                "content": doc,
                "metadata": m,
                "distance": round(d, 4) if d is not None else None,
                "source": m.get("source", m.get("filename", "unknown")),
                "timestamp": m.get("timestamp", m.get("created_at", "")),
            })
        return out
    except Exception as e:
        return []


def list_documents(collection_name: str, offset: int = 0, limit: int = 20) -> dict:
    try:
        cols = list_collections()
        col = next((c for c in cols if c.get("name") == collection_name), None)
        if not col:
            return {"documents": [], "total": 0}
        col_id = col.get("id", col.get("name", ""))
        result = _post(f"/collections/{col_id}/get", {
            "limit": limit,
            "offset": offset,
            "include": ["documents", "metadatas"],
        })
        docs = result.get("documents", [])
        metas = result.get("metadatas", [])
        ids = result.get("ids", [])
        count_raw = _get(f"/collections/{col_id}/count")
        total = count_raw if isinstance(count_raw, int) else count_raw.get("count", len(docs))
        items = []
        for i, doc in enumerate(docs):
            m = metas[i] if i < len(metas) else {}
            items.append({
                "id": ids[i] if i < len(ids) else str(i),
                "content": doc,
                "metadata": m,
                "source": m.get("source", m.get("filename", "unknown")),
                "timestamp": m.get("timestamp", m.get("created_at", "")),
            })
        return {"documents": items, "total": total}
    except Exception:
        return {"documents": [], "total": 0}


def get_threat_actors() -> list[dict]:
    try:
        cols = list_collections()
        col = next((c for c in cols if c.get("name") == "security_docs"), None)
        if not col and cols:
            col = cols[0]
        if not col:
            return []
        col_id = col.get("id", col.get("name", ""))
        result = _post(f"/collections/{col_id}/get", {
            "where": {"source": {"$contains": "ta_profile"}},
            "include": ["documents", "metadatas"],
            "limit": 200,
        })
        docs = result.get("documents", [])
        metas = result.get("metadatas", [])
        ids = result.get("ids", [])
        actors = []
        for i, doc in enumerate(docs):
            m = metas[i] if i < len(metas) else {}
            actors.append({
                "id": ids[i] if i < len(ids) else str(i),
                "content": doc,
                "metadata": m,
                "name": m.get("group_name", m.get("name", ids[i] if i < len(ids) else f"actor_{i}")),
                "last_updated": m.get("timestamp", m.get("updated_at", "")),
            })
        return actors
    except Exception:
        return []
