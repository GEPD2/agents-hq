import os
import re
import ast
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services.agent_monitor import AGENTS_BASE_DIR

router = APIRouter()

ENV_FILE = Path(AGENTS_BASE_DIR) / "agent_01_osint" / ".env"
AGENT09_FILE = Path(AGENTS_BASE_DIR) / "agent_09_market_intel" / "agent_09_market_intel.py"
AGENT10_FILE = Path(AGENTS_BASE_DIR) / "agent_10_darkweb" / "agent_10_darkweb.py"

ENV_KEYS = ["OTX_API_KEY", "FINNHUB_API_KEY", "INTELX_API_KEY", "HIBP_API_KEY", "VT_API_KEY",
            "SHODAN_API_KEY", "GREYNOISE_API_KEY", "CENSYS_ID", "CENSYS_SECRET",
            "VIRUSTOTAL_KEY", "HUNTER_KEY", "URLSCAN_KEY", "SECURITYTRAILS_KEY",
            "IPINFO_TOKEN", "ABUSEIPDB_KEY",
            # Alert config
            "ALERT_WEBHOOK_URL", "SMTP_HOST", "SMTP_PORT",
            "SMTP_USER", "SMTP_PASSWORD", "ALERT_EMAIL_TO"]


def _read_env() -> dict:
    result = {}
    if not ENV_FILE.exists():
        return result
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k in ENV_KEYS:
            masked = v[:4] + "***" + v[-2:] if len(v) > 6 else "***"
            result[k] = masked
    return result


def _write_env_key(key: str, value: str) -> None:
    if key not in ENV_KEYS:
        raise ValueError(f"Key {key} not in allowed list")
    if not ENV_FILE.exists():
        ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
        ENV_FILE.touch()
    lines = ENV_FILE.read_text().splitlines()
    new_line = f'{key}="{value}"'
    found = False
    for i, line in enumerate(lines):
        if line.strip().startswith(f"{key}=") or line.strip().startswith(f"{key} ="):
            lines[i] = new_line
            found = True
            break
    if not found:
        lines.append(new_line)
    ENV_FILE.write_text("\n".join(lines) + "\n")


def _read_watchlist() -> dict:
    if not AGENT09_FILE.exists():
        return {}
    content = AGENT09_FILE.read_text()
    m = re.search(r'WATCHLIST_BY_SECTOR\s*=\s*(\{[^}]+\})', content, re.DOTALL)
    if not m:
        return {}
    try:
        return ast.literal_eval(m.group(1))
    except Exception:
        return {}


def _write_watchlist(data: dict) -> None:
    if not AGENT09_FILE.exists():
        raise FileNotFoundError("Agent-09 script not found")
    content = AGENT09_FILE.read_text()
    import json
    new_block = "WATCHLIST_BY_SECTOR = " + repr(data)
    content = re.sub(
        r'WATCHLIST_BY_SECTOR\s*=\s*\{[^}]+\}',
        new_block,
        content,
        flags=re.DOTALL,
    )
    AGENT09_FILE.write_text(content)


def _read_onion_targets() -> dict:
    if not AGENT10_FILE.exists():
        return {}
    content = AGENT10_FILE.read_text()
    m = re.search(r'ONION_TARGETS\s*:\s*dict\[str,\s*str\]\s*=\s*(\{[^}]*\})', content, re.DOTALL)
    if not m:
        return {}
    try:
        return ast.literal_eval(m.group(1))
    except Exception:
        return {}


def _write_onion_targets(data: dict) -> None:
    if not AGENT10_FILE.exists():
        raise FileNotFoundError("Agent-10 script not found")
    content = AGENT10_FILE.read_text()
    lines = [f'    "{k}": "{v}",' for k, v in data.items()]
    inner = "\n".join(lines)
    new_block = f'ONION_TARGETS: dict[str, str] = {{\n{inner}\n}}'
    content = re.sub(
        r'ONION_TARGETS\s*:\s*dict\[str,\s*str\]\s*=\s*\{[^}]*\}',
        new_block,
        content,
        flags=re.DOTALL,
    )
    AGENT10_FILE.write_text(content)


# ── Routes ────────────────────────────────────────────────────────────────────

class EnvKeyBody(BaseModel):
    key: str
    value: str


class WatchlistBody(BaseModel):
    watchlist: dict


class OnionBody(BaseModel):
    targets: dict


class AlertsBody(BaseModel):
    config: dict


@router.get("/settings")
async def get_settings():
    return {
        "env": _read_env(),
        "watchlist": _read_watchlist(),
        "onion_targets": _read_onion_targets(),
        "env_file_exists": ENV_FILE.exists(),
    }


@router.post("/settings/env")
async def update_env(body: EnvKeyBody):
    try:
        _write_env_key(body.key, body.value)
        return {"updated": body.key}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/settings/watchlist")
async def update_watchlist(body: WatchlistBody):
    try:
        _write_watchlist(body.watchlist)
        return {"updated": True}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/settings/onion")
async def update_onion(body: OnionBody):
    try:
        _write_onion_targets(body.targets)
        return {"updated": True}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/settings/alerts")
async def get_alerts():
    from services.alerter import get_alert_config_masked, ALERT_KEYS
    cfg = get_alert_config_masked()
    return {k: cfg.get(k, "") for k in ALERT_KEYS}


@router.post("/settings/alerts")
async def save_alerts(body: AlertsBody):
    from services.alerter import ALERT_KEYS as AKEYS
    saved = []
    for key, value in body.config.items():
        if key in AKEYS:
            try:
                _write_env_key(key, str(value))
                saved.append(key)
            except Exception:
                pass
    return {"saved": saved}


@router.post("/alerts/test")
async def test_alert():
    from services.alerter import fire_alerts
    results = fire_alerts("test_report.md", "Test Agent", 1)
    if not results:
        return {"ok": False, "detail": "No alert channels configured"}
    return {"ok": True, "results": results}
