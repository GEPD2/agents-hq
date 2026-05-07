import os
import asyncio
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional

AGENTS_BASE_DIR = os.environ.get("AGENTS_BASE_DIR", "/agents-hq")

AGENTS: dict[str, dict] = {
    "01": {
        "name": "OSINT Collector",
        "port": 8765,
        "container": "agents-agent01",
        "script": "agent_01_osint/agent_01_osint_v3.py",
        "webhook_path": "/webhook/agent01",
        "type": "webhook",
        "description": "Domain, IP, email, phone OSINT via 20+ sources",
        "params": ["target", "mode"],
        "schedules": [],
    },
    "02": {
        "name": "Task Researcher",
        "port": None,
        "container": None,
        "script": "agent_02_task/agent_02_task.py",
        "webhook_path": None,
        "type": "subprocess",
        "description": "Deep task-specific research via web + LLM synthesis",
        "params": ["target"],
        "schedules": [],
    },
    "03": {
        "name": "RAG Knowledge Base",
        "port": None,
        "container": None,
        "script": None,
        "webhook_path": None,
        "type": "kb",
        "description": "MySQL relational store — not a process",
        "params": [],
        "schedules": [],
    },
    "04": {
        "name": "Master Orchestrator",
        "port": 8764,
        "container": "agents-agent04",
        "script": "agent_04_orchestrator/agent_04_orchestrator.py",
        "webhook_path": "/webhook/agent04",
        "type": "webhook",
        "description": "Coordinates multi-agent workflows",
        "params": ["target"],
        "schedules": [],
    },
    "05": {
        "name": "Red Team",
        "port": 8763,
        "container": "agents-agent05",
        "script": "agent_05_redteam/agent_05_redteam.py",
        "webhook_path": "/webhook/agent05",
        "type": "webhook",
        "description": "Active recon, vuln scan, exploitation chains",
        "params": ["target"],
        "schedules": [],
    },
    "06": {
        "name": "Ghidra RE",
        "port": 8766,
        "container": "agents-agent06",
        "script": "agent_06_ghidra/agent_06_ghidra.py",
        "webhook_path": "/webhook/agent06",
        "type": "webhook",
        "description": "Binary reverse engineering via Ghidra + LLM analysis",
        "params": ["target"],
        "schedules": [],
    },
    "07": {
        "name": "Crypto Analysis",
        "port": 8767,
        "container": "agents-agent07",
        "script": "agent_07_crypto/agent_07_crypto.py",
        "webhook_path": "/webhook/agent07",
        "type": "webhook",
        "description": "Hash cracking, cipher analysis, crypto forensics",
        "params": ["target"],
        "schedules": [],
    },
    "08": {
        "name": "News Intel",
        "port": 8768,
        "container": "agents-agent08",
        "script": "agent_08_news_intel/agent_08_news_intel.py",
        "webhook_path": "/webhook/agent08",
        "type": "webhook",
        "description": "Threat intel aggregation from 30+ security news sources",
        "params": ["since"],
        "schedules": ["Every 6h"],
    },
    "09": {
        "name": "Market Intel",
        "port": 8769,
        "container": "agents-agent09",
        "script": "agent_09_market_intel/agent_09_market_intel.py",
        "webhook_path": "/webhook/agent09",
        "type": "webhook",
        "description": "Security-sector market monitoring and financial threat intel",
        "params": ["since"],
        "schedules": ["Daily 13:30 UTC"],
    },
    "10": {
        "name": "Dark Web Monitor",
        "port": 8770,
        "container": "agents-agent10",
        "script": "agent_10_darkweb/agent_10_darkweb.py",
        "webhook_path": "/webhook/agent10",
        "type": "webhook",
        "description": "Ransomware groups, dark web markets, threat actor tracking",
        "params": ["since", "tor"],
        "schedules": ["Every 12h"],
    },
}

# Maps agent_id -> {"started": datetime, "job_id": str}
_running_jobs: dict[str, dict] = {}


def is_running(agent_id: str) -> bool:
    return agent_id in _running_jobs


def set_running(agent_id: str, job_id: str) -> None:
    _running_jobs[agent_id] = {"started": datetime.utcnow(), "job_id": job_id}


def clear_running(agent_id: str) -> None:
    _running_jobs.pop(agent_id, None)


def get_run_info(agent_id: str) -> Optional[dict]:
    return _running_jobs.get(agent_id)


def _http_health(port: int, timeout: int = 3) -> bool:
    try:
        url = f"http://localhost:{port}/health"
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


async def check_agent_health(agent_id: str) -> str:
    agent = AGENTS.get(agent_id)
    if not agent:
        return "unknown"
    if agent["type"] in ("subprocess", "kb"):
        return "n/a"
    if is_running(agent_id):
        return "running"
    port = agent["port"]
    ok = await asyncio.get_event_loop().run_in_executor(None, _http_health, port)
    return "online" if ok else "offline"


async def check_all_agents() -> dict[str, str]:
    tasks = {aid: check_agent_health(aid) for aid in AGENTS}
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    return {aid: (r if isinstance(r, str) else "offline") for aid, r in zip(tasks.keys(), results)}


def _check_service(host: str, port: int, path: str = "/", timeout: int = 3) -> bool:
    try:
        url = f"http://{host}:{port}{path}"
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status < 500
    except urllib.error.HTTPError as e:
        return e.code < 500
    except Exception:
        return False


def _check_mysql(timeout: int = 3) -> bool:
    from services.mysql_client import is_available
    return is_available()


async def platform_status() -> dict:
    loop = asyncio.get_event_loop()
    ollama = await loop.run_in_executor(None, lambda: _check_service("localhost", 11434, "/api/tags"))
    mysql  = await loop.run_in_executor(None, _check_mysql)
    n8n    = await loop.run_in_executor(None, lambda: _check_service("localhost", 5678, "/healthz"))
    tor    = await loop.run_in_executor(None, lambda: _check_service("localhost", 9050, "/"))
    agents_health = await check_all_agents()
    return {
        "ollama": ollama,
        "mysql": mysql,
        "n8n": n8n,
        "tor": tor,
        "agents": agents_health,
    }
