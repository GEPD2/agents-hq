from fastapi import APIRouter

from services.geo_store import get_map_ips

router = APIRouter()


@router.get("/map/ips")
async def map_ips():
    return get_map_ips()
