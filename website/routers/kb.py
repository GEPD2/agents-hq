from fastapi import APIRouter, HTTPException, Query

from services import mysql_client as db

router = APIRouter()


@router.get("/kb/stats")
async def kb_stats():
    return db.list_collections()


@router.get("/kb/search")
async def kb_search(q: str = Query(..., min_length=1), n: int = Query(10, ge=1, le=50)):
    return db.search(q, n_results=n)


@router.get("/kb/collections/{name}")
async def kb_collection(name: str, offset: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)):
    return db.list_documents(name, offset=offset, limit=limit)


@router.get("/kb/threat-actors")
async def threat_actors():
    return db.get_threat_actors()


@router.get("/kb/threat-actors/{name}")
async def threat_actor(name: str):
    actors = db.get_threat_actors()
    actor = next((a for a in actors if a.get("name", "").lower() == name.lower()), None)
    if not actor:
        raise HTTPException(status_code=404, detail="Threat actor not found")
    return actor
