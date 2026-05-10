import re

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator
from typing import Optional

from services.agent_monitor import AGENTS, check_agent_health, check_all_agents, platform_status, get_run_info
from services.log_streamer import spawn_agent, stream_job, stream_docker_logs

router = APIRouter()

# Allowlist: printable ASCII minus shell metacharacters that have no
# legitimate use in a scan target (IP, domain, URL, file path, keyword).
_TARGET_RE = re.compile(r'^[A-Za-z0-9 ./:_@?=&%+,\-\[\]{}#!*]+$')
_TARGET_MAX_LEN = 512


class RunParams(BaseModel):
    target: Optional[str] = None
    mode: Optional[str] = "adaptive"
    since: Optional[int] = 6
    tor: Optional[bool] = False

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if len(v) > _TARGET_MAX_LEN:
            raise ValueError(f"target must be ≤ {_TARGET_MAX_LEN} characters")
        if "\x00" in v or "\n" in v or "\r" in v:
            raise ValueError("target contains invalid characters")
        if v and not _TARGET_RE.match(v):
            raise ValueError("target contains disallowed characters")
        return v


@router.get("/status")
async def get_status():
    return await platform_status()


@router.get("/agents")
async def get_agents():
    health = await check_all_agents()
    result = []
    for agent_id, agent in AGENTS.items():
        status = health.get(agent_id, "unknown")
        run_info = get_run_info(agent_id)
        result.append({
            "id": agent_id,
            "name": agent["name"],
            "type": agent["type"],
            "port": agent["port"],
            "description": agent["description"],
            "params": agent["params"],
            "schedules": agent["schedules"],
            "status": status,
            "running": run_info is not None,
            "run_started": run_info["started"].isoformat() if run_info else None,
        })
    return result


@router.get("/agents/{agent_id}/health")
async def agent_health(agent_id: str):
    if agent_id not in AGENTS:
        raise HTTPException(status_code=404, detail="Agent not found")
    status = await check_agent_health(agent_id)
    return {"id": agent_id, "status": status}


@router.post("/agents/{agent_id}/run")
async def run_agent(agent_id: str, params: RunParams):
    if agent_id not in AGENTS:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent = AGENTS[agent_id]
    if agent["type"] == "kb":
        raise HTTPException(status_code=400, detail="Agent-03 is the RAG knowledge base, not a runnable process")

    run_params = {}
    if params.target:
        run_params["target"] = params.target
    if params.mode:
        run_params["mode"] = params.mode
    if params.since is not None:
        run_params["since"] = params.since
    if params.tor:
        run_params["tor"] = params.tor

    try:
        job_id = await spawn_agent(agent_id, run_params)
        return {"job_id": job_id, "agent_id": agent_id, "status": "started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agents/{agent_id}/stream")
async def stream_agent(agent_id: str, job_id: Optional[str] = None):
    if agent_id not in AGENTS:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = AGENTS[agent_id]

    async def _generate():
        if job_id:
            async for chunk in stream_job(job_id):
                yield chunk
        elif agent.get("container"):
            async for chunk in stream_docker_logs(agent["container"]):
                yield chunk
        else:
            yield "data: No active job and no container to tail\n\n"
            yield "data: [DONE]\n\n"

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
