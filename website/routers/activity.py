import asyncio

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from services import findings_feed

router = APIRouter()


@router.get("/activity/recent")
async def activity_recent(limit: int = 30):
    limit = max(1, min(limit, 100))
    loop = asyncio.get_event_loop()
    items = await loop.run_in_executor(None, findings_feed.recent_findings, limit)
    return {"findings": items}


@router.get("/activity/stream")
async def activity_stream():
    return StreamingResponse(
        findings_feed.stream_findings(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
