import re
import os
from datetime import datetime
from pathlib import Path

REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "/agents-hq/reports"))

AGENT_PREFIXES = {
    "osint": "01",
    "recon": "02",
    "re_": "06",
    "intel": "08",
    "market": "09",
    "darkweb": "10",
    "dark_web": "10",
}

IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
HASH_RE = re.compile(r'\b[a-fA-F0-9]{32,64}\b')
ONION_RE = re.compile(r'\b[a-z2-7]{16,56}\.onion\b', re.IGNORECASE)
WALLET_BTC_RE = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
WALLET_ETH_RE = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|mil|ru|cn|de|uk|fr|nl|info|biz|xyz|top|cc|tk|pw)\b')

PRIORITY_RE = re.compile(r'\b(CRITICAL|HIGH|MEDIUM|LOW)\b')


def get_agent_type(filename: str) -> str:
    lower = filename.lower()
    for prefix, agent_id in AGENT_PREFIXES.items():
        if lower.startswith(prefix):
            return agent_id
    return "unknown"


def parse_priority_counts(content: str) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for m in PRIORITY_RE.finditer(content):
        level = m.group(1).upper()
        if level in counts:
            counts[level] += 1
    return counts


def extract_iocs(content: str) -> dict:
    ips = list(set(IP_RE.findall(content)))
    # filter out version numbers like 1.2.3.4 that look like IPs but are common
    ips = [ip for ip in ips if not ip.startswith("127.") and not ip.startswith("0.")]
    cves = list(set(CVE_RE.findall(content)))
    onions = list(set(ONION_RE.findall(content)))
    wallets_btc = list(set(WALLET_BTC_RE.findall(content)))
    wallets_eth = list(set(WALLET_ETH_RE.findall(content)))
    # hashes: only standalone (not part of longer strings), 32 or 64 chars
    hashes_raw = HASH_RE.findall(content)
    hashes = list(set(h for h in hashes_raw if len(h) in (32, 40, 64)))
    domains_raw = DOMAIN_RE.findall(content)
    domains = list(set(d for d in domains_raw if len(d) > 4))
    return {
        "ips": ips[:50],
        "cves": cves[:50],
        "onions": onions[:50],
        "wallets": wallets_btc[:20] + wallets_eth[:20],
        "hashes": hashes[:30],
        "domains": domains[:50],
    }


def list_reports() -> list[dict]:
    if not REPORTS_DIR.exists():
        return []
    reports = []
    for f in sorted(REPORTS_DIR.glob("*.md"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            stat = f.stat()
            content = f.read_text(encoding="utf-8", errors="replace")
            counts = parse_priority_counts(content)
            reports.append({
                "filename": f.name,
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "agent": get_agent_type(f.name),
                "priority_counts": counts,
            })
        except Exception:
            pass
    return reports


def read_report(filename: str) -> str | None:
    safe = Path(filename).name  # strip any path traversal
    path = REPORTS_DIR / safe
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def delete_report(filename: str) -> bool:
    safe = Path(filename).name
    path = REPORTS_DIR / safe
    if not path.exists():
        return False
    path.unlink()
    return True


def recent_reports(limit: int = 20) -> list[dict]:
    return list_reports()[:limit]
