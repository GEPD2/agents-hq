import json
import os
import smtplib
import urllib.request
from email.message import EmailMessage
from pathlib import Path

from services.agent_monitor import AGENTS_BASE_DIR
from services.report_parser import parse_priority_counts, read_report, get_agent_type

ENV_FILE = Path(AGENTS_BASE_DIR) / "agent_01_osint" / ".env"
WEBSITE_URL = os.environ.get("WEBSITE_URL", "http://localhost:8080")

ALERT_KEYS = [
    "ALERT_WEBHOOK_URL",
    "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "ALERT_EMAIL_TO",
]

_AGENT_NAMES = {
    "01": "OSINT Collector", "02": "Task Researcher", "05": "Red Team",
    "06": "Ghidra RE",       "07": "Crypto Analysis", "08": "News Intel",
    "09": "Market Intel",    "10": "Dark Web Monitor",
}


def get_alert_config() -> dict:
    cfg: dict[str, str] = {}
    if not ENV_FILE.exists():
        return cfg
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k in ALERT_KEYS:
            cfg[k] = v
    return cfg


def get_alert_config_masked() -> dict:
    cfg = get_alert_config()
    result = {}
    for k in ALERT_KEYS:
        v = cfg.get(k, "")
        if k in ("SMTP_PASSWORD", "ALERT_WEBHOOK_URL") and len(v) > 6:
            result[k] = v[:4] + "***" + v[-2:]
        else:
            result[k] = v
    return result


def send_webhook(url: str, payload: dict) -> bool:
    if not url:
        return False
    try:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception as e:
        print(f"[ALERT] Webhook failed: {e}")
        return False


def send_email(cfg: dict, subject: str, body: str) -> bool:
    host = cfg.get("SMTP_HOST", "")
    port = int(cfg.get("SMTP_PORT", 587) or 587)
    user = cfg.get("SMTP_USER", "")
    pw   = cfg.get("SMTP_PASSWORD", "")
    to   = cfg.get("ALERT_EMAIL_TO", "")
    if not all([host, user, pw, to]):
        return False
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"]    = user
        msg["To"]      = to
        msg.set_content(body)
        with smtplib.SMTP(host, port, timeout=15) as s:
            s.ehlo()
            s.starttls()
            s.login(user, pw)
            s.send_message(msg)
        return True
    except Exception as e:
        print(f"[ALERT] Email failed: {e}")
        return False


def fire_alerts(filename: str, agent_name: str, critical_count: int) -> dict:
    cfg = get_alert_config()
    report_url = f"{WEBSITE_URL}/reports/{filename}"

    subject = f"[AGENTS-HQ] CRITICAL — {agent_name}: {critical_count} finding(s)"
    text_body = (
        f"AGENTS-HQ Critical Alert\n"
        f"{'=' * 40}\n"
        f"Agent:    {agent_name}\n"
        f"Report:   {filename}\n"
        f"CRITICAL: {critical_count}\n"
        f"URL:      {report_url}\n"
    )
    webhook_payload = {
        "text": (
            f"*[AGENTS-HQ] CRITICAL Alert*\n"
            f"*Agent:* {agent_name}\n"
            f"*Report:* `{filename}`\n"
            f"*CRITICAL findings:* {critical_count}\n"
            f"*View report:* {report_url}"
        ),
        "agent":          agent_name,
        "filename":       filename,
        "critical_count": critical_count,
        "report_url":     report_url,
    }

    results: dict[str, bool] = {}
    if cfg.get("ALERT_WEBHOOK_URL"):
        results["webhook"] = send_webhook(cfg["ALERT_WEBHOOK_URL"], webhook_payload)
    if cfg.get("SMTP_HOST") and cfg.get("ALERT_EMAIL_TO"):
        results["email"] = send_email(cfg, subject, text_body)
    return results


def check_and_alert(filename: str) -> dict | None:
    content = read_report(filename)
    if not content:
        return None
    counts = parse_priority_counts(content)
    crit = counts.get("CRITICAL", 0)
    if crit == 0:
        return None
    agent_id   = get_agent_type(filename)
    agent_name = _AGENT_NAMES.get(agent_id, f"Agent-{agent_id}")
    print(f"[ALERT] {crit} CRITICAL in {filename} — firing alerts")
    return fire_alerts(filename, agent_name, crit)
