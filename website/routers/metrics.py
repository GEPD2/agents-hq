from fastapi import APIRouter

from services.metrics_store import get_metrics

router = APIRouter()


@router.get("/metrics")
async def metrics():
    return get_metrics()
