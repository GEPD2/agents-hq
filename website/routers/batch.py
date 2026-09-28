from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional

from services.batch_runner import parse_targets, start_batch, batch_status, stream_batch, active_batches
from services.security import rate_limiter

router = APIRouter()

_MAX_CONCURRENT_BATCHES = 3


class BatchParams(BaseModel):
    targets: str = ""
    mode: Optional[str] = "adaptive"


@router.post("/batch/start")
async def batch_start(params: BatchParams):
    if not rate_limiter.allow("batch_start", limit=5, window=60):
        raise HTTPException(status_code=429, detail="Too many batch starts; wait a moment")
    if active_batches() >= _MAX_CONCURRENT_BATCHES:
        raise HTTPException(status_code=429, detail="Too many batches running; let some finish")
    targets = parse_targets(params.targets)
    if not targets:
        raise HTTPException(status_code=400, detail="No valid targets provided")
    return start_batch(targets, params.mode or "adaptive")


@router.get("/batch/{batch_id}/status")
async def batch_get_status(batch_id: str):
    status = batch_status(batch_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Batch not found")
    return status


@router.get("/batch/{batch_id}/stream")
async def batch_stream(batch_id: str):
    return StreamingResponse(
        stream_batch(batch_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
