import asyncio
import subprocess
import time
import uuid
import os
from pathlib import Path
from typing import AsyncGenerator

from services.agent_monitor import AGENTS, AGENTS_BASE_DIR, set_running, clear_running

REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "/agents-hq/reports"))


def _find_new_report(since_ts: float) -> str | None:
    if not REPORTS_DIR.exists():
        return None
    candidates = [
        f for f in REPORTS_DIR.glob("*.md")
        if f.stat().st_mtime >= since_ts
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda f: f.stat().st_mtime).name


def _try_alert(since_ts: float) -> None:
    try:
        report = _find_new_report(since_ts)
        if report:
            from services.alerter import check_and_alert
            check_and_alert(report)
    except Exception as e:
        print(f"[ALERT] post-run check failed: {e}")

# job_id -> {"process": Popen, "queue": asyncio.Queue, "agent_id": str}
_jobs: dict[str, dict] = {}


async def spawn_agent(agent_id: str, params: dict) -> str:
    agent = AGENTS.get(agent_id)
    if not agent:
        raise ValueError(f"Unknown agent: {agent_id}")

    job_id = str(uuid.uuid4())[:8]

    if agent["type"] == "webhook":
        job_id = await _spawn_via_webhook(agent_id, agent, params, job_id)
    elif agent["type"] == "subprocess":
        job_id = await _spawn_subprocess(agent_id, agent, params, job_id)
    else:
        raise ValueError(f"Agent {agent_id} cannot be triggered (type: {agent['type']})")

    set_running(agent_id, job_id)
    return job_id


async def _spawn_via_webhook(agent_id: str, agent: dict, params: dict, job_id: str) -> str:
    import json
    import urllib.request

    port = agent["port"]
    path = agent["webhook_path"]
    url = f"http://localhost:{port}{path}"

    body = json.dumps(params).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    q: asyncio.Queue = asyncio.Queue()
    _jobs[job_id] = {"queue": q, "agent_id": agent_id, "type": "webhook"}

    async def _fire():
        start_ts = time.time()
        try:
            await q.put(f"[TRIGGER] POST {url} body={params}")
            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(None, lambda: urllib.request.urlopen(req, timeout=300))
            data = json.loads(resp.read())
            result_text = data.get("result", data.get("status", str(data)))
            for line in str(result_text).splitlines():
                await q.put(line)
            await q.put("[DONE]")
        except Exception as e:
            await q.put(f"[ERROR] {e}")
            await q.put("[DONE]")
        finally:
            clear_running(agent_id)
            _try_alert(start_ts)

    asyncio.create_task(_fire())
    return job_id


async def _spawn_subprocess(agent_id: str, agent: dict, params: dict, job_id: str) -> str:
    script = agent.get("script")
    if not script:
        raise ValueError(f"No script for agent {agent_id}")

    script_path = Path(AGENTS_BASE_DIR) / script
    cmd = ["python3", str(script_path)]

    target = params.get("target", "")
    if target:
        # Reject null bytes / newlines defensively; validation also happens at the router layer.
        if any(c in target for c in ("\x00", "\n", "\r")):
            raise ValueError("target contains invalid characters")
        cmd += ["--target", target]

    since = params.get("since")
    if since is not None:
        cmd += ["--since", str(int(since))]

    q: asyncio.Queue = asyncio.Queue()

    env = os.environ.copy()
    env_file = Path(AGENTS_BASE_DIR) / "agent_01_osint" / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip('"').strip("'")

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
    )

    _jobs[job_id] = {"queue": q, "process": process, "agent_id": agent_id, "type": "subprocess"}

    async def _reader():
        start_ts = time.time()
        loop = asyncio.get_event_loop()
        try:
            while True:
                line = await loop.run_in_executor(None, process.stdout.readline)
                if not line:
                    break
                await q.put(line.rstrip())
        finally:
            process.wait()
            await q.put("[DONE]")
            clear_running(agent_id)
            _try_alert(start_ts)

    asyncio.create_task(_reader())
    return job_id


async def stream_job(job_id: str) -> AsyncGenerator[str, None]:
    job = _jobs.get(job_id)
    if not job:
        yield "data: [ERROR] Job not found\n\n"
        yield "data: [DONE]\n\n"
        return

    q = job["queue"]
    while True:
        try:
            line = await asyncio.wait_for(q.get(), timeout=60.0)
            yield f"data: {line}\n\n"
            if line == "[DONE]":
                break
        except asyncio.TimeoutError:
            yield "data: [HEARTBEAT]\n\n"


async def stream_docker_logs(container: str) -> AsyncGenerator[str, None]:
    process = await asyncio.create_subprocess_exec(
        "docker", "logs", container, "--follow", "--tail", "50",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        while True:
            line = await asyncio.wait_for(process.stdout.readline(), timeout=60.0)
            if not line:
                break
            yield f"data: {line.decode().rstrip()}\n\n"
    except asyncio.TimeoutError:
        yield "data: [HEARTBEAT]\n\n"
    finally:
        process.kill()
