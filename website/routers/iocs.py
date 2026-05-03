from fastapi import APIRouter, HTTPException, Query
from services.ioc_store import (
    ingest_report, ingest_all, list_iocs,
    get_ioc_detail, correlate_ioc, get_stats,
)

router = APIRouter()


@router.get("/iocs/stats")
async def api_ioc_stats():
    return get_stats()


@router.post("/iocs/ingest-all")
async def api_ingest_all():
    return ingest_all()


@router.post("/iocs/ingest/{filename:path}")
async def api_ingest(filename: str):
    count = ingest_report(filename)
    return {"filename": filename, "iocs_stored": count}


@router.get("/iocs/correlate/{ioc_type}/{value:path}")
async def api_correlate(ioc_type: str, value: str):
    return correlate_ioc(ioc_type, value)


@router.get("/iocs/{ioc_type}/{value:path}")
async def api_ioc_detail(ioc_type: str, value: str):
    detail = get_ioc_detail(ioc_type, value)
    if detail is None:
        raise HTTPException(status_code=404, detail="IOC not found")
    return detail


@router.get("/iocs")
async def api_list_iocs(type: str = Query(None), page: int = Query(1)):
    return list_iocs(itype=type, page=page)
