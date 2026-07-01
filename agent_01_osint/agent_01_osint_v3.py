#!/usr/bin/env python3
"""
AGENTS-HQ — Agent-01 OSINT Intelligence Agent v2
Full-spectrum autonomous open-source intelligence platform

Scan Modes:
  --mode fast     10-15 steps  — triage, quick answer
  --mode deep     20-25 steps  — full surface mapping
  --mode adaptive auto-scaled  — depth based on target type
  --mode insane   no limit     — scorched earth, full dossier

Intelligence Sources:
  Shodan        — host services, CVE tags, banners
  GreyNoise     — IP noise classification, scanner/attacker/benign
  Censys        — TLS/cert deep search, host fingerprinting
  VirusTotal    — domain/IP/hash reputation, malware associations
  SpiderFoot    — 200+ module automated correlation engine
  urlscan.io    — live website screenshots, DOM, outbound links
  Wayback Machine — historical snapshots, deleted content
  BGPView       — full routing table, ASN, prefix hijack detection
  ThreatFox     — IOC feeds, malware C2 infrastructure
  OTX AlienVault — threat pulses, adversary TTPs
  crt.sh        — certificate transparency, subdomain discovery
  HackerTarget  — reverse IP, co-hosted domains
  Hunter.io     — email pattern discovery
  HIBP          — breach database lookup
  Numverify     — phone carrier/region/line type
  ipinfo.io     — geolocation, ASN, org, abuse contacts
  SecurityTrails — historical DNS, WHOIS history, subdomains
  AbuseIPDB     — IP abuse reports, confidence score, attack categories
  DuckDuckGo    — open web search, Google dorking
  WHOIS         — registration, registrar, contacts
  DNS (dig)     — full record enumeration
  Nominatim     — reverse geocoding for GPS coordinates
  exiftool      — EXIF/GPS extraction from images

Usage:
  python3 agent_01_osint_v2.py --target example.com --mode fast
  python3 agent_01_osint_v2.py --target 93.184.216.34 --mode deep
  python3 agent_01_osint_v2.py --target user@example.com --mode adaptive
  python3 agent_01_osint_v2.py --target "Acme Corp" --mode insane
  python3 agent_01_osint_v2.py --target +306912345678 --mode fast
  python3 agent_01_osint_v2.py --image photo.jpg --mode deep
  python3 agent_01_osint_v2.py --interactive
  python3 agent_01_osint_v2.py --n8n-server
"""

import sys, json, subprocess, argparse, requests, re, os, base64
import struct, socket, time, ipaddress
from datetime import datetime
from pathlib import Path

# ── Config ────────────────────────────────────────────────────
OLLAMA_HOST    = "localhost"
OLLAMA_PORT    = 11434
AGENT_MODEL    = "qwen2.5:14b"
CHROMA_HOST    = "localhost"
CHROMA_PORT    = 8000
REPORTS_DIR    = Path(__file__).parent.parent / "reports"
TIMEOUT_WEB    = 25
TIMEOUT_DNS    = 10
N8N_WEBHOOK_PORT = int(os.environ.get("N8N_WEBHOOK_PORT", "8765"))

# Mode iteration limits
MODE_LIMITS = {
    "fast":     15,
    "deep":     25,
    "adaptive": 30,
    "insane":   60,
}

# Mode tool sequences (ordered priority lists)
MODE_WORKFLOWS = {
    "domain": {
        "fast":     ["whois","dns_lookup","shodan_lookup","web_search","file_write"],
        "deep":     ["whois","dns_lookup","cert_search","shodan_lookup","greynoise_lookup",
                     "censys_lookup","virustotal_lookup","reverse_ip","asn_lookup",
                     "securitytrails_lookup","email_harvest","urlscan_lookup",
                     "wayback_lookup","web_search","file_write"],
        "adaptive": ["whois","dns_lookup","cert_search","shodan_lookup","greynoise_lookup",
                     "censys_lookup","virustotal_lookup","reverse_ip","asn_lookup",
                     "securitytrails_lookup","email_harvest","urlscan_lookup",
                     "wayback_lookup","web_search","file_write"],
        "insane":   ["whois","dns_lookup","cert_search","shodan_lookup","greynoise_lookup",
                     "censys_lookup","virustotal_lookup","reverse_ip","asn_lookup",
                     "securitytrails_lookup","email_harvest","urlscan_lookup",
                     "wayback_lookup","bgp_lookup","threatfox_lookup","otx_lookup",
                     "abuseipdb_lookup","spiderfoot_scan",
                     "web_search","web_search","web_search","file_write"],
    },
    "ip": {
        "fast":     ["whois","shodan_lookup","greynoise_lookup","web_search","file_write"],
        "deep":     ["whois","shodan_lookup","greynoise_lookup","censys_lookup",
                     "virustotal_lookup","abuseipdb_lookup","ipinfo_lookup",
                     "reverse_ip","asn_lookup","dns_lookup",
                     "threatfox_lookup","web_search","file_write"],
        "adaptive": ["whois","shodan_lookup","greynoise_lookup","censys_lookup",
                     "virustotal_lookup","abuseipdb_lookup","ipinfo_lookup",
                     "reverse_ip","asn_lookup","dns_lookup",
                     "threatfox_lookup","otx_lookup","web_search","file_write"],
        "insane":   ["whois","shodan_lookup","greynoise_lookup","censys_lookup",
                     "virustotal_lookup","abuseipdb_lookup","ipinfo_lookup",
                     "reverse_ip","asn_lookup","dns_lookup",
                     "threatfox_lookup","otx_lookup","bgp_lookup","urlscan_lookup",
                     "spiderfoot_scan","web_search","web_search","file_write"],
    },
    "email": {
        "fast":     ["whois","dns_lookup","email_harvest","web_search","file_write"],
        "deep":     ["whois","dns_lookup","email_harvest","cert_search","shodan_lookup",
                     "virustotal_lookup","web_search","web_search","file_write"],
        "adaptive": ["whois","dns_lookup","email_harvest","cert_search","shodan_lookup",
                     "greynoise_lookup","virustotal_lookup","web_search","web_search","file_write"],
        "insane":   ["whois","dns_lookup","email_harvest","cert_search","shodan_lookup",
                     "greynoise_lookup","censys_lookup","virustotal_lookup","threatfox_lookup",
                     "otx_lookup","spiderfoot_scan","web_search","web_search",
                     "web_search","file_write"],
    },
    "phone": {
        "fast":     ["phone_lookup","web_search","file_write"],
        "deep":     ["phone_lookup","web_search","web_search","web_search","file_write"],
        "adaptive": ["phone_lookup","web_search","web_search","web_search","file_write"],
        "insane":   ["phone_lookup","web_search","web_search","web_search",
                     "web_search","spiderfoot_scan","file_write"],
    },
    "company": {
        "fast":     ["web_search","whois","shodan_lookup","file_write"],
        "deep":     ["web_search","whois","cert_search","shodan_lookup","greynoise_lookup",
                     "censys_lookup","email_harvest","virustotal_lookup",
                     "web_search","web_search","file_write"],
        "adaptive": ["web_search","whois","cert_search","shodan_lookup","greynoise_lookup",
                     "censys_lookup","email_harvest","virustotal_lookup","otx_lookup",
                     "urlscan_lookup","web_search","web_search","file_write"],
        "insane":   ["web_search","whois","cert_search","shodan_lookup","greynoise_lookup",
                     "censys_lookup","virustotal_lookup","email_harvest","reverse_ip",
                     "asn_lookup","bgp_lookup","threatfox_lookup","otx_lookup",
                     "urlscan_lookup","wayback_lookup","spiderfoot_scan",
                     "web_search","web_search","web_search","file_write"],
    },
    "image": {
        "fast":     ["image_intel","web_search","file_write"],
        "deep":     ["image_intel","web_search","web_search","file_write"],
        "adaptive": ["image_intel","web_search","web_search","file_write"],
        "insane":   ["image_intel","web_search","web_search","web_search",
                     "web_search","file_write"],
    },
}

# ── ANSI Colors ───────────────────────────────────────────────
C_THINK  = "\033[38;5;244m"
C_HEAD   = "\033[38;5;39m"
C_TOOL   = "\033[38;5;208m"
C_OBS    = "\033[38;5;82m"
C_WARN   = "\033[38;5;196m"
C_ACT    = "\033[38;5;226m"
C_INFO   = "\033[38;5;51m"
C_MODE   = "\033[38;5;201m"
C_INSANE = "\033[38;5;196m"
C_RESET  = "\033[0m"

MODE_COLORS = {
    "fast":     "\033[38;5;82m",
    "deep":     "\033[38;5;39m",
    "adaptive": "\033[38;5;208m",
    "insane":   "\033[38;5;196m",
}
MODE_LABELS = {
    "fast":     "⚡ FAST RECON",
    "deep":     "🔍 DEEP INTEL",
    "adaptive": "🎯 ADAPTIVE",
    "insane":   "☠  INSANE MODE — SCORCHED EARTH",
}

def cprint(color, text, end="\n"):
    print(f"{color}{text}{C_RESET}", end=end, flush=True)

# ── Target type detection ─────────────────────────────────────
def detect_target_type(target):
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        return "ip"
    if re.match(r'^[a-f0-9:]+$', target, re.IGNORECASE) and ':' in target:
        return "ipv6"
    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', target):
        return "email"
    if re.match(r'^\+?[\d\s\-\(\)]{7,20}$', target) and sum(c.isdigit() for c in target) >= 7:
        return "phone"
    if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', target):
        return "domain"
    return "company"

# ── API Keys (loaded from .env) ───────────────────────────────
def load_env():
    env_file = Path(__file__).parent / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                os.environ.setdefault(k.strip(), v.strip())

load_env()
SHODAN_API_KEY   = os.environ.get("SHODAN_API_KEY", "")
GREYNOISE_KEY    = os.environ.get("GREYNOISE_API_KEY", "")
CENSYS_TOKEN     = os.environ.get("CENSYS_API_TOKEN", "")
VIRUSTOTAL_KEY   = os.environ.get("VIRUSTOTAL_API_KEY", "")
HIBP_API_KEY     = os.environ.get("HIBP_API_KEY", "")
NUMVERIFY_KEY    = os.environ.get("NUMVERIFY_KEY", "")
HUNTER_KEY       = os.environ.get("HUNTER_API_KEY", "")
URLSCAN_KEY        = os.environ.get("URLSCAN_API_KEY", "")
OTX_KEY            = os.environ.get("OTX_API_KEY", "")
SECURITYTRAILS_KEY = os.environ.get("SECURITYTRAILS_KEY", "")
IPINFO_TOKEN       = os.environ.get("IPINFO_TOKEN", "")
ABUSEIPDB_KEY      = os.environ.get("ABUSEIPDB_KEY", "")

FORMAT_REMINDER = (
    "\n\nFORMAT REMINDER:\n"
    "  Tool: THOUGHT: ... | ACTION: <toolname> | INPUT: ...\n"
    "  Done: THOUGHT: ... | FINAL_ANSWER: ... (NOT 'ACTION: FINAL_ANSWER')\n"
    "  Keep thinking SHORT — 3-4 sentences max then write action immediately."
)

# ══════════════════════════════════════════════════════════════
# TOOLS
# ══════════════════════════════════════════════════════════════

def tool_whois(target):
    cprint(C_TOOL, f"  [WHOIS] {target}")
    try:
        r = subprocess.run(["whois", target], capture_output=True, text=True, timeout=30)
        out = r.stdout or r.stderr
        if len(out) > 5000:
            out = out[:5000] + "\n...[truncated]"
        keys = ["Registrar:","Registrant","Creation Date","Updated Date","Expiry Date",
                "Expiration Date","Name Server","DNSSEC","OrgName:","NetRange:","CIDR:",
                "ASNumber:","Country:","Admin Email","Tech Email","Abuse","Status:"]
        important = [l.strip() for l in out.split('\n')
                     if any(k.lower() in l.lower() for k in keys)]
        return f"[WHOIS] {target}:\n" + "\n".join(important[:50]) if important else f"[WHOIS] Raw:\n{out[:3000]}"
    except Exception as e:
        return f"[WHOIS] Error: {e}"


def tool_dns_lookup(target):
    cprint(C_TOOL, f"  [DNS] {target}")
    results = []
    domain = target
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        try:
            h = socket.gethostbyaddr(target)
            return f"[DNS] PTR for {target}: {h[0]}"
        except Exception:
            return f"[DNS] No reverse DNS for {target}"
    for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA"]:
        try:
            r = subprocess.run(["dig","+short",rtype,domain],
                               capture_output=True, text=True, timeout=TIMEOUT_DNS)
            for line in r.stdout.strip().split('\n'):
                if line.strip():
                    results.append(f"{rtype}: {line.strip()}")
        except Exception:
            pass
    for prefix in ["","_dmarc."]:
        try:
            r = subprocess.run(["dig","+short","TXT",f"{prefix}{domain}"],
                               capture_output=True, text=True, timeout=TIMEOUT_DNS)
            txt = r.stdout.strip()
            if txt and ("spf" in txt.lower() or "dmarc" in txt.lower()):
                results.append(f"{'DMARC' if prefix else 'SPF'}: {txt[:300]}")
        except Exception:
            pass
    return f"[DNS] {domain}:\n" + "\n".join(results[:40]) if results else f"[DNS] No records for {domain}"


def tool_cert_search(target):
    cprint(C_TOOL, f"  [CERT] crt.sh — {target}")
    domain = re.sub(r'^https?://', '', target).split('/')[0].strip()
    if '@' in domain:
        domain = domain.split('@')[1]
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json",
                        timeout=TIMEOUT_WEB, headers={"User-Agent": "AGENTS-HQ/2.0"})
        data = r.json()
        subdomains, orgs, issuers = set(), set(), set()
        for cert in data:
            for sub in cert.get("name_value","").split('\n'):
                sub = sub.strip().lstrip('*.')
                if sub and domain in sub:
                    subdomains.add(sub)
            if cert.get("issuer_name"):
                issuers.add(cert["issuer_name"][:80])
        out = [f"[CERT] {len(subdomains)} names for {domain}:"]
        for sub in sorted(subdomains)[:60]:
            out.append(f"  {sub}")
        if issuers:
            out.append(f"\nIssuers: {' | '.join(list(issuers)[:3])}")
        return "\n".join(out)
    except Exception as e:
        return f"[CERT] Error: {e}"


def tool_shodan_lookup(target):
    cprint(C_TOOL, f"  [SHODAN] {target}")
    if not SHODAN_API_KEY:
        return "[SHODAN] No API key — set SHODAN_API_KEY in .env"
    try:
        import shodan as shodan_lib
        api = shodan_lib.Shodan(SHODAN_API_KEY)
        ip = target
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            try:
                ip = socket.gethostbyname(target)
            except Exception:
                # Use search instead
                results = api.search(f"hostname:{target}")
                out = [f"[SHODAN] hostname:{target} — {results['total']} results:"]
                for m in results.get('matches', [])[:8]:
                    out.append(f"  {m.get('ip_str','?')}:{m.get('port','?')} "
                               f"| {m.get('product','')} {m.get('version','')} "
                               f"| {m.get('org','?')}")
                return "\n".join(out)
        host = api.host(ip)
        out = [f"[SHODAN] Host: {ip}",
               f"  Org: {host.get('org','?')}",
               f"  ISP: {host.get('isp','?')}",
               f"  OS: {host.get('os','?')}",
               f"  Country: {host.get('country_name','?')}",
               f"  City: {host.get('city','?')}",
               f"  Last update: {host.get('last_update','?')}",
               f"  Ports: {host.get('ports',[])}",
               f"  Hostnames: {host.get('hostnames',[])}",
               f"  Domains: {host.get('domains',[])}",
               f"  Tags: {host.get('tags',[])}"]
        vulns = host.get('vulns', {})
        if vulns:
            out.append(f"  ⚠ CVEs: {', '.join(list(vulns.keys())[:15])}")
        for svc in host.get('data', [])[:8]:
            port = svc.get('port','?')
            transport = svc.get('transport','tcp')
            product = svc.get('product','')
            version = svc.get('version','')
            banner  = svc.get('data','')[:150].replace('\n',' ')
            out.append(f"\n  [{port}/{transport}] {product} {version}")
            if banner.strip():
                out.append(f"    Banner: {banner}")
            cpe = svc.get('cpe', [])
            if cpe:
                out.append(f"    CPE: {cpe}")
        return "\n".join(out)
    except ImportError:
        # Fallback to REST API
        try:
            ip = target
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
                try:
                    ip = socket.gethostbyname(target)
                except Exception:
                    pass
            r = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
                            params={"key": SHODAN_API_KEY}, timeout=TIMEOUT_WEB)
            if r.status_code == 404:
                return f"[SHODAN] No data for {target}"
            d = r.json()
            out = [f"[SHODAN] {ip} | {d.get('org','?')} | {d.get('country_name','?')}",
                   f"  Ports: {d.get('ports',[])}",
                   f"  Vulns: {list(d.get('vulns',{}).keys())[:10]}"]
            for svc in d.get('data',[])[:6]:
                out.append(f"  [{svc.get('port','?')}/{svc.get('transport','tcp')}] "
                           f"{svc.get('product','')} {svc.get('version','')}")
            return "\n".join(out)
        except Exception as e:
            return f"[SHODAN] REST Error: {e}"
    except Exception as e:
        return f"[SHODAN] Error: {e}"


def tool_greynoise_lookup(target):
    cprint(C_TOOL, f"  [GREYNOISE] {target}")
    ip = target
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            return f"[GREYNOISE] Could not resolve {target}"
    headers = {"User-Agent": "AGENTS-HQ/2.0"}
    if GREYNOISE_KEY:
        headers["key"] = GREYNOISE_KEY
    try:
        # Community API (no key needed but limited)
        r = requests.get(f"https://api.greynoise.io/v3/community/{ip}",
                        headers=headers, timeout=TIMEOUT_WEB)
        if r.status_code == 200:
            d = r.json()
            out = [f"[GREYNOISE] {ip}:",
                   f"  Noise: {d.get('noise', '?')}",
                   f"  Riot: {d.get('riot', '?')}  (known benign service)",
                   f"  Classification: {d.get('classification', 'unknown')}",
                   f"  Name: {d.get('name', '?')}",
                   f"  Link: {d.get('link', '')}",
                   f"  Last seen: {d.get('last_seen', '?')}",
                   f"  Message: {d.get('message', '')}"]
            return "\n".join(out)
        elif r.status_code == 404:
            return f"[GREYNOISE] {ip} — not in GreyNoise dataset (not observed scanning internet)"
        else:
            return f"[GREYNOISE] Status {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return f"[GREYNOISE] Error: {e}"


def tool_censys_lookup(target):
    cprint(C_TOOL, f"  [CENSYS] {target}")
    if not CENSYS_TOKEN:
        return "[CENSYS] No token — set CENSYS_API_TOKEN in .env"
    headers = {
        "Authorization": f"Bearer {CENSYS_TOKEN}",
        "User-Agent": "AGENTS-HQ/2.0",
        "Accept": "application/json",
    }
    try:
        ip = target
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            try:
                ip = socket.gethostbyname(target)
            except Exception:
                pass
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            r = requests.get(f"https://search.censys.io/api/v2/hosts/{ip}",
                             headers=headers, timeout=TIMEOUT_WEB)
            if r.status_code == 200:
                d = r.json().get("result", {})
                out = [f"[CENSYS] Host: {ip}"]
                out.append(f"  Autonomous System: {d.get('autonomous_system',{}).get('name','?')} "
                           f"(ASN {d.get('autonomous_system',{}).get('asn','?')})")
                out.append(f"  Country: {d.get('location',{}).get('country','?')}")
                out.append(f"  City: {d.get('location',{}).get('city','?')}")
                out.append(f"  Labels: {d.get('labels',[])}")
                for svc in d.get('services', [])[:8]:
                    port  = svc.get('port','?')
                    proto = svc.get('transport_protocol','')
                    name  = svc.get('service_name','')
                    banner = svc.get('banner','')[:100]
                    out.append(f"  [{port}/{proto}] {name} | {banner}")
                    tls = svc.get('tls', {})
                    if tls:
                        cert = tls.get('certificates', {}).get('leaf_data', {})
                        subj = cert.get('subject', {})
                        out.append(f"    TLS CN: {subj.get('common_name','?')} "
                                  f"| Issuer: {cert.get('issuer',{}).get('organization','?')}")
                return "\n".join(out)
            elif r.status_code == 404:
                return f"[CENSYS] No data for {ip}"
            elif r.status_code == 401:
                return "[CENSYS] Unauthorized — check CENSYS_API_TOKEN in .env"
            else:
                return f"[CENSYS] Status {r.status_code}: {r.text[:200]}"
        else:
            # Domain/hostname — use v2 hosts search
            r = requests.get(
                "https://search.censys.io/api/v2/hosts/search",
                headers=headers,
                params={"q": f"dns.reverse_dns.reverse_dns: {target}", "per_page": 10},
                timeout=TIMEOUT_WEB
            )
            if r.status_code == 200:
                hits = r.json().get("result", {}).get("hits", [])
                out  = [f"[CENSYS] Hosts matching {target}: {len(hits)} found"]
                for hit in hits[:8]:
                    out.append(f"  IP: {hit.get('ip','?')} | "
                               f"AS: {hit.get('autonomous_system',{}).get('name','?')} | "
                               f"Country: {hit.get('location',{}).get('country','?')}")
                    for svc in hit.get('services', [])[:4]:
                        out.append(f"    [{svc.get('port','?')}/{svc.get('transport_protocol','')}] "
                                   f"{svc.get('service_name','')}")
                return "\n".join(out)
            return f"[CENSYS] Status {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return f"[CENSYS] Error: {e}"


def tool_virustotal_lookup(target):
    cprint(C_TOOL, f"  [VIRUSTOTAL] {target}")
    if not VIRUSTOTAL_KEY:
        return "[VIRUSTOTAL] No API key — set VIRUSTOTAL_API_KEY in .env"
    headers = {"x-apikey": VIRUSTOTAL_KEY, "User-Agent": "AGENTS-HQ/2.0"}
    try:
        # Determine endpoint
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
        elif '@' in target:
            domain = target.split('@')[1]
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        elif re.match(r'^[a-fA-F0-9]{32,64}$', target):
            url = f"https://www.virustotal.com/api/v3/files/{target}"
        else:
            domain = re.sub(r'^https?://', '', target).split('/')[0]
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"

        r = requests.get(url, headers=headers, timeout=TIMEOUT_WEB)
        if r.status_code == 200:
            d = r.json().get("data", {}).get("attributes", {})
            stats = d.get("last_analysis_stats", {})
            out = [f"[VIRUSTOTAL] {target}:"]
            out.append(f"  Malicious: {stats.get('malicious',0)} | "
                      f"Suspicious: {stats.get('suspicious',0)} | "
                      f"Harmless: {stats.get('harmless',0)} | "
                      f"Undetected: {stats.get('undetected',0)}")
            reputation = d.get("reputation", 0)
            out.append(f"  Reputation score: {reputation}")
            categories = d.get("categories", {})
            if categories:
                out.append(f"  Categories: {list(set(categories.values()))[:8]}")
            tags = d.get("tags", [])
            if tags:
                out.append(f"  Tags: {tags[:10]}")
            # Top malicious detections
            results = d.get("last_analysis_results", {})
            detections = [(engine, res.get("result","")) for engine, res in results.items()
                         if res.get("category") == "malicious"]
            if detections:
                out.append(f"  Top detections:")
                for engine, result in detections[:6]:
                    out.append(f"    {engine}: {result}")
            # Historical data
            if d.get("creation_date"):
                out.append(f"  Creation date: {datetime.fromtimestamp(d['creation_date'])}")
            if d.get("last_dns_records"):
                out.append(f"  DNS records: {len(d['last_dns_records'])} found")
            return "\n".join(out)
        elif r.status_code == 404:
            return f"[VIRUSTOTAL] {target} — not found in database"
        elif r.status_code == 429:
            return "[VIRUSTOTAL] Rate limited — wait 60 seconds (free tier: 4 req/min)"
        else:
            return f"[VIRUSTOTAL] Status {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return f"[VIRUSTOTAL] Error: {e}"


def tool_threatfox_lookup(target):
    cprint(C_TOOL, f"  [THREATFOX] {target}")
    try:
        payload = {"query": "search_ioc", "search_term": target}
        r = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                         json=payload, timeout=TIMEOUT_WEB,
                         headers={"User-Agent": "AGENTS-HQ/2.0"})
        d = r.json()
        if d.get("query_status") == "no_results":
            return f"[THREATFOX] {target} — no IOCs found in ThreatFox database"
        iocs = d.get("data", [])
        if not iocs:
            return f"[THREATFOX] {target} — no results"
        out = [f"[THREATFOX] {len(iocs)} IOCs found for {target}:"]
        for ioc in iocs[:10]:
            out.append(f"  IOC: {ioc.get('ioc','?')}")
            out.append(f"    Type: {ioc.get('ioc_type','?')} | "
                      f"Threat: {ioc.get('threat_type','?')} | "
                      f"Malware: {ioc.get('malware','?')}")
            out.append(f"    Confidence: {ioc.get('confidence_level','?')}% | "
                      f"First seen: {ioc.get('first_seen','?')}")
            tags = ioc.get('tags', [])
            if tags:
                out.append(f"    Tags: {tags}")
        return "\n".join(out)
    except Exception as e:
        return f"[THREATFOX] Error: {e}"


def tool_otx_lookup(target):
    cprint(C_TOOL, f"  [OTX] AlienVault — {target}")
    headers = {"User-Agent": "AGENTS-HQ/2.0"}
    if OTX_KEY:
        headers["X-OTX-API-KEY"] = OTX_KEY
    try:
        # Determine indicator type
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            ind_type = "IPv4"
            sections = "general/reputation/geo/malware/url_list/passive_dns"
        elif '@' in target:
            ind_type = "email"
            sections = "general"
            target = target.split('@')[1]
            ind_type = "domain"
        elif re.match(r'^[a-fA-F0-9]{32,64}$', target):
            ind_type = "file"
            sections = "general/analysis"
        else:
            ind_type = "domain"
            sections = "general/reputation/geo/malware/url_list/passive_dns/whois"

        out = [f"[OTX] AlienVault indicator: {target} [{ind_type}]"]
        for section in sections.split('/'):
            try:
                url = f"https://otx.alienvault.com/api/v1/indicators/{ind_type}/{target}/{section}"
                r = requests.get(url, headers=headers, timeout=TIMEOUT_WEB)
                if r.status_code == 200:
                    d = r.json()
                    if section == "general":
                        pulse_count = d.get("pulse_info", {}).get("count", 0)
                        out.append(f"  Pulse count: {pulse_count} threat intelligence pulses")
                        if pulse_count > 0:
                            pulses = d.get("pulse_info", {}).get("pulses", [])
                            for p in pulses[:5]:
                                out.append(f"    Pulse: {p.get('name','?')} "
                                          f"| Tags: {p.get('tags',[][:3])}")
                    elif section == "reputation":
                        rep = d.get("reputation", 0)
                        activities = d.get("activities", [])
                        out.append(f"  Reputation: {rep}")
                        if activities:
                            out.append(f"  Activities: {[a.get('name','') for a in activities[:5]]}")
                    elif section == "geo":
                        out.append(f"  Geo: {d.get('country_name','?')} — "
                                  f"{d.get('city','?')} | ASN: {d.get('asn','?')}")
                    elif section == "malware":
                        count = d.get("count", 0)
                        if count:
                            out.append(f"  Malware samples: {count}")
                            for sample in d.get("data", [])[:3]:
                                out.append(f"    Hash: {sample.get('hash','?')} "
                                          f"| Date: {sample.get('date','?')}")
                    elif section == "passive_dns":
                        dns_count = d.get("count", 0)
                        if dns_count:
                            out.append(f"  Passive DNS: {dns_count} records")
                            for rec in d.get("passive_dns", [])[:5]:
                                out.append(f"    {rec.get('hostname','?')} → "
                                          f"{rec.get('address','?')} ({rec.get('first','?')})")
            except Exception:
                pass
        return "\n".join(out)
    except Exception as e:
        return f"[OTX] Error: {e}"


def tool_urlscan_lookup(target):
    cprint(C_TOOL, f"  [URLSCAN] {target}")
    headers = {"User-Agent": "AGENTS-HQ/2.0"}
    if URLSCAN_KEY:
        headers["API-Key"] = URLSCAN_KEY
    try:
        # Search existing scans
        domain = re.sub(r'^https?://', '', target).split('/')[0]
        r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5",
                        headers=headers, timeout=TIMEOUT_WEB)
        if r.status_code == 200:
            results = r.json().get("results", [])
            out = [f"[URLSCAN] {domain} — {len(results)} existing scans:"]
            for scan in results[:5]:
                task = scan.get("task", {})
                page = scan.get("page", {})
                stats = scan.get("stats", {})
                out.append(f"\n  Scan: {task.get('time','?')}")
                out.append(f"    URL: {task.get('url','?')}")
                out.append(f"    IP: {page.get('ip','?')} | Country: {page.get('country','?')}")
                out.append(f"    Server: {page.get('server','?')}")
                out.append(f"    Title: {page.get('title','?')[:80]}")
                out.append(f"    Requests: {stats.get('requests',0)} | "
                          f"Scripts: {stats.get('scriptCount',0)} | "
                          f"Cookies: {stats.get('cookieCount',0)}")
                if scan.get("verdicts",{}).get("overall",{}).get("malicious"):
                    out.append(f"    ⚠ MALICIOUS: {scan['verdicts']['overall'].get('categories',[])}")
                out.append(f"    Report: https://urlscan.io/result/{scan.get('task',{}).get('uuid','')}/")

            # Submit new scan if key available
            if URLSCAN_KEY:
                submit_r = requests.post("https://urlscan.io/api/v1/scan/",
                    headers={**headers, "Content-Type": "application/json"},
                    json={"url": f"https://{domain}", "visibility": "private"},
                    timeout=TIMEOUT_WEB)
                if submit_r.status_code in [200, 201]:
                    scan_id = submit_r.json().get("uuid","")
                    out.append(f"\n  New scan submitted: https://urlscan.io/result/{scan_id}/")
                    out.append(f"  (Results available in ~30 seconds)")
            return "\n".join(out)
        return f"[URLSCAN] Status {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return f"[URLSCAN] Error: {e}"


def tool_wayback_lookup(target):
    cprint(C_TOOL, f"  [WAYBACK] {target}")
    domain = re.sub(r'^https?://', '', target).split('/')[0]
    try:
        # Availability check
        r = requests.get(
            f"https://archive.org/wayback/available?url={domain}",
            timeout=TIMEOUT_WEB, headers={"User-Agent": "AGENTS-HQ/2.0"})
        avail = r.json()
        snapshot = avail.get("archived_snapshots", {}).get("closest", {})

        out = [f"[WAYBACK] {domain}:"]
        if snapshot.get("available"):
            out.append(f"  Latest snapshot: {snapshot.get('timestamp','?')}")
            out.append(f"  URL: {snapshot.get('url','?')}")
            out.append(f"  Status: {snapshot.get('status','?')}")

        # CDX API — historical URL list
        cdx_r = requests.get(
            f"https://web.archive.org/cdx/search/cdx",
            params={"url": f"*.{domain}/*", "output": "json", "limit": 20,
                    "fl": "timestamp,original,statuscode,mimetype",
                    "filter": "statuscode:200", "collapse": "urlkey"},
            timeout=TIMEOUT_WEB, headers={"User-Agent": "AGENTS-HQ/2.0"})

        if cdx_r.status_code == 200:
            rows = cdx_r.json()
            if len(rows) > 1:
                out.append(f"\n  Historical URLs ({len(rows)-1} found):")
                for row in rows[1:15]:  # skip header row
                    ts, url, status, mime = row
                    # Flag interesting paths
                    flag = ""
                    interesting = ["admin","login","backup","config","api","wp-admin",
                                  ".git","password","secret","private",".env",".sql",
                                  "phpmyadmin","panel","console","db","database"]
                    if any(i in url.lower() for i in interesting):
                        flag = " ⚠ INTERESTING"
                    out.append(f"  [{ts[:8]}] {url[:100]}{flag}")
        return "\n".join(out)
    except Exception as e:
        return f"[WAYBACK] Error: {e}"


def tool_bgp_lookup(target):
    cprint(C_TOOL, f"  [BGP] {target}")
    ip = target
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            return f"[BGP] Could not resolve {target}"
    try:
        out = [f"[BGP] Routing data for {ip}:"]

        # BGPView IP lookup
        r = requests.get(f"https://api.bgpview.io/ip/{ip}",
                        timeout=TIMEOUT_WEB, headers={"User-Agent": "AGENTS-HQ/2.0"})
        if r.status_code == 200:
            d = r.json().get("data", {})
            for prefix in d.get("prefixes", []):
                out.append(f"  Prefix: {prefix.get('prefix','?')}")
                asn_info = prefix.get("asn", {})
                out.append(f"  ASN: AS{asn_info.get('asn','?')} — {asn_info.get('name','?')}")
                out.append(f"  Country: {prefix.get('country_code','?')}")
                out.append(f"  Description: {asn_info.get('description','?')}")
                out.append(f"  Allocation: {prefix.get('allocation',{}).get('allocation','?')}")

        # BGPView ASN details
        asn_match = re.search(r'AS(\d+)', "\n".join(out))
        if asn_match:
            asn_num = asn_match.group(1)
            asn_r = requests.get(f"https://api.bgpview.io/asn/{asn_num}",
                                 timeout=TIMEOUT_WEB, headers={"User-Agent": "AGENTS-HQ/2.0"})
            if asn_r.status_code == 200:
                asn_d = asn_r.json().get("data", {})
                out.append(f"\n  ASN Details: AS{asn_num}")
                out.append(f"  Name: {asn_d.get('name','?')}")
                out.append(f"  Description: {asn_d.get('description_short','?')}")
                out.append(f"  Country: {asn_d.get('country_code','?')}")
                out.append(f"  Websites: {asn_d.get('website','?')}")
                emails = asn_d.get('email_contacts', [])
                if emails:
                    out.append(f"  Abuse emails: {emails[:3]}")

            # Prefixes for this ASN
            prefix_r = requests.get(f"https://api.bgpview.io/asn/{asn_num}/prefixes",
                                    timeout=TIMEOUT_WEB, headers={"User-Agent": "AGENTS-HQ/2.0"})
            if prefix_r.status_code == 200:
                prefix_d = prefix_r.json().get("data", {})
                v4 = prefix_d.get("ipv4_prefixes", [])
                out.append(f"\n  IPv4 prefixes: {len(v4)}")
                for p in v4[:8]:
                    out.append(f"    {p.get('prefix','?')} — {p.get('description','?')[:60]}")

        return "\n".join(out)
    except Exception as e:
        return f"[BGP] Error: {e}"


def tool_reverse_ip(target):
    cprint(C_TOOL, f"  [REVERSE_IP] {target}")
    ip = target
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            return f"[REVERSE_IP] Could not resolve {target}"
    results = [f"[REVERSE_IP] Co-hosted domains on {ip}:"]
    try:
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                        timeout=TIMEOUT_WEB, headers={"User-Agent": "AGENTS-HQ/2.0"})
        if r.status_code == 200 and "error" not in r.text.lower():
            domains = [d.strip() for d in r.text.strip().split('\n') if d.strip()]
            results.append(f"  {len(domains)} domains found:")
            for d in domains[:40]:
                results.append(f"    {d}")
        else:
            results.append(f"  HackerTarget: {r.text[:200]}")
    except Exception as e:
        results.append(f"  Error: {e}")
    return "\n".join(results)


def tool_asn_lookup(target):
    cprint(C_TOOL, f"  [ASN] {target}")
    ip = target
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            pass
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json",
                        timeout=TIMEOUT_WEB, headers={"User-Agent": "AGENTS-HQ/2.0"})
        d = r.json()
        out = [f"[ASN] {ip}:",
               f"  Org/ASN: {d.get('org','?')}",
               f"  Location: {d.get('city','?')}, {d.get('region','?')}, {d.get('country','?')}",
               f"  Timezone: {d.get('timezone','?')}",
               f"  Hostname: {d.get('hostname','?')}"]
        if d.get('loc'):
            out.append(f"  Coordinates: {d['loc']}")
            out.append(f"  Maps: https://maps.google.com/?q={d['loc']}")
        return "\n".join(out)
    except Exception as e:
        return f"[ASN] Error: {e}"


def tool_email_harvest(target):
    cprint(C_TOOL, f"  [EMAIL] {target}")
    results = []
    if '@' in target:
        email = target
        domain = target.split('@')[1]
        if HIBP_API_KEY:
            try:
                r = requests.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                    headers={"hibp-api-key": HIBP_API_KEY, "User-Agent": "AGENTS-HQ/2.0"},
                    timeout=TIMEOUT_WEB)
                if r.status_code == 200:
                    breaches = r.json()
                    results.append(f"[HIBP] {len(breaches)} breaches for {email}:")
                    for b in breaches[:10]:
                        results.append(f"  {b['Name']} ({b['BreachDate']}) — {b.get('DataClasses',[][:4])}")
                elif r.status_code == 404:
                    results.append(f"[HIBP] {email} — clean, not in any breach")
                else:
                    results.append(f"[HIBP] Status {r.status_code}")
            except Exception as e:
                results.append(f"[HIBP] Error: {e}")
        else:
            results.append("[HIBP] Set HIBP_API_KEY in .env")
    else:
        domain = target
        if HUNTER_KEY:
            try:
                r = requests.get("https://api.hunter.io/v2/domain-search",
                                params={"domain": domain, "limit": 15, "api_key": HUNTER_KEY},
                                timeout=TIMEOUT_WEB)
                if r.status_code == 200:
                    d = r.json().get("data", {})
                    pattern = d.get("pattern", "?")
                    emails = d.get("emails", [])
                    total = d.get("total", 0)
                    results.append(f"[HUNTER] {domain}: {total} emails found")
                    results.append(f"  Pattern: {pattern}@{domain}")
                    for e in emails[:12]:
                        results.append(f"  {e['value']} ({e.get('type','?')}) "
                                      f"confidence:{e.get('confidence','?')}%")
                        if e.get('sources'):
                            results.append(f"    Source: {e['sources'][0].get('uri','?')[:80]}")
            except Exception as e:
                results.append(f"[HUNTER] Error: {e}")
        else:
            results.append("[HUNTER] Set HUNTER_API_KEY in .env for email discovery")
    return "\n".join(results) if results else f"[EMAIL] No data for {target}"


def tool_phone_lookup(target):
    cprint(C_TOOL, f"  [PHONE] {target}")
    clean = re.sub(r'[\s\-\(\)]', '', target)
    results = [f"[PHONE] {target}:"]
    if NUMVERIFY_KEY:
        try:
            r = requests.get("http://apilayer.net/api/validate",
                            params={"access_key": NUMVERIFY_KEY, "number": clean,
                                    "country_code": "", "format": "1"},
                            timeout=TIMEOUT_WEB)
            d = r.json()
            if d.get("valid"):
                results += [f"  Country: {d.get('country_name','?')} ({d.get('country_code','?')})",
                            f"  Carrier: {d.get('carrier','?')}",
                            f"  Line type: {d.get('line_type','?')}",
                            f"  Location: {d.get('location','?')}",
                            f"  International: {d.get('international_format','?')}"]
            else:
                results.append("  Number appears invalid or not in database")
        except Exception as e:
            results.append(f"  Numverify error: {e}")
    else:
        results.append("  Set NUMVERIFY_KEY in .env for carrier/line type lookup")
        cc_map = {'+1':'USA/Canada','+44':'UK','+49':'Germany','+33':'France',
                  '+39':'Italy','+34':'Spain','+7':'Russia','+86':'China',
                  '+91':'India','+55':'Brazil','+61':'Australia','+81':'Japan',
                  '+30':'Greece','+971':'UAE','+972':'Israel','+90':'Turkey'}
        for cc, country in cc_map.items():
            if clean.startswith(cc):
                results.append(f"  Country code: {cc} → {country}")
                break
    # Web mentions
    try:
        q = f'"{clean}" OR "{target}"'
        r = requests.get("https://html.duckduckgo.com/html/?q=" + requests.utils.quote(q),
                        timeout=TIMEOUT_WEB, headers={"User-Agent": "Mozilla/5.0"})
        snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', r.text, re.DOTALL)
        snippets = [re.sub(r'<[^>]+>', '', s).strip() for s in snippets[:5]]
        if snippets:
            results.append("\n  Web mentions:")
            for s in snippets:
                results.append(f"    {s[:200]}")
    except Exception:
        pass
    return "\n".join(results)


def tool_image_intel(filepath):
    cprint(C_TOOL, f"  [IMAGE] {filepath}")
    path = Path(filepath)
    if not path.exists():
        return f"[IMAGE] File not found: {filepath}"
    results = [f"[IMAGE] {path.name} ({path.stat().st_size} bytes):"]
    try:
        r = subprocess.run(["exiftool", "-json", str(path)],
                          capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            data = json.loads(r.stdout)[0]
            important = ["Make","Model","Software","DateTime","DateTimeOriginal",
                        "GPSLatitude","GPSLongitude","GPSAltitude","GPSLatitudeRef",
                        "GPSLongitudeRef","GPSSpeed","GPSImgDirection","Author",
                        "Creator","Copyright","Artist","Comment","UserComment",
                        "CameraSerialNumber","LensModel","ImageWidth","ImageHeight",
                        "MimeType","FileModifyDate","DocumentName","ImageDescription"]
            for tag in important:
                val = data.get(tag)
                if val:
                    results.append(f"  {tag}: {val}")
            lat = data.get("GPSLatitude")
            lon = data.get("GPSLongitude")
            if lat and lon:
                def dms_to_dd(dms):
                    if isinstance(dms, (int, float)):
                        return float(dms)
                    parts = re.findall(r'[\d.]+', str(dms))
                    if len(parts) >= 3:
                        return float(parts[0]) + float(parts[1])/60 + float(parts[2])/3600
                    return float(parts[0]) if parts else 0.0
                lat_dd = dms_to_dd(lat) * (-1 if data.get("GPSLatitudeRef","N")=="S" else 1)
                lon_dd = dms_to_dd(lon) * (-1 if data.get("GPSLongitudeRef","E")=="W" else 1)
                results.append(f"\n  === GPS FOUND ===")
                results.append(f"  Decimal: {lat_dd:.6f}, {lon_dd:.6f}")
                results.append(f"  Google Maps: https://maps.google.com/?q={lat_dd},{lon_dd}")
                results.append(f"  OpenStreetMap: https://www.openstreetmap.org/?mlat={lat_dd}&mlon={lon_dd}")
                try:
                    geo = requests.get("https://nominatim.openstreetmap.org/reverse",
                                      params={"lat":lat_dd,"lon":lon_dd,"format":"json"},
                                      timeout=TIMEOUT_WEB,
                                      headers={"User-Agent":"AGENTS-HQ/2.0"})
                    loc = geo.json()
                    results.append(f"  Address: {loc.get('display_name','?')}")
                except Exception:
                    pass
        return "\n".join(results)
    except FileNotFoundError:
        results.append("  exiftool not found — install: sudo apt install libimage-exiftool-perl")
        return "\n".join(results)
    except Exception as e:
        return f"[IMAGE] Error: {e}"


def tool_web_search(query):
    cprint(C_TOOL, f"  [WEB] {query}")
    try:
        r = requests.get("https://html.duckduckgo.com/html/?q=" + requests.utils.quote(query),
                        timeout=TIMEOUT_WEB, headers={"User-Agent": "Mozilla/5.0"})
        snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', r.text, re.DOTALL)
        titles   = re.findall(r'class="result__a"[^>]*>(.*?)</a>', r.text, re.DOTALL)
        snippets = [re.sub(r'<[^>]+>', '', s).strip() for s in snippets[:8]]
        titles   = [re.sub(r'<[^>]+>', '', t).strip() for t in titles[:8]]
        if not snippets:
            return f"[WEB] No results: {query}"
        out = [f"[WEB] {query}:"]
        for t, s in zip(titles, snippets):
            out.append(f"  [{t[:80]}]\n    {s[:250]}")
        return "\n".join(out)
    except Exception as e:
        return f"[WEB] Error: {e}"


def tool_spiderfoot_scan(target):
    cprint(C_TOOL, f"  [SPIDERFOOT] {target}")
    try:
        r = subprocess.run(["sfp", "--version"], capture_output=True, text=True, timeout=10)
        sf_available = r.returncode == 0
    except FileNotFoundError:
        try:
            r = subprocess.run(["python3", "-m", "spiderfoot", "--version"],
                              capture_output=True, text=True, timeout=10)
            sf_available = r.returncode == 0
        except Exception:
            sf_available = False

    if not sf_available:
        return ("[SPIDERFOOT] Not installed or not in PATH.\n"
                "Install: pip install spiderfoot\n"
                "Or: git clone https://github.com/smicallef/spiderfoot && cd spiderfoot && pip install -r requirements.txt\n"
                "Skipping SpiderFoot — continuing with other tools.")
    try:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        out_file = REPORTS_DIR / f"spiderfoot_{re.sub(r'[^\w]','_',target)}_{ts}.json"
        # Run SpiderFoot with passive modules only
        cmd = ["sfp", "-s", target, "-t", "INTERNET_NAME,IP_ADDRESS,EMAILADDR",
               "-m", "sfp_dnsresolve,sfp_ssl,sfp_whois,sfp_dns,sfp_dnscommonsrv,"
                    "sfp_hackertarget,sfp_certspotter,sfp_shodan,sfp_virustotal,"
                    "sfp_threatcrowd,sfp_passivedns,sfp_riskiq",
               "-o", "json", "-q", str(out_file)]
        cprint(C_INFO, "  [SPIDERFOOT] Scanning — this may take 2-5 minutes...")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if out_file.exists():
            data = json.loads(out_file.read_text())
            out = [f"[SPIDERFOOT] Scan complete — {len(data)} findings:"]
            # Summarize by type
            by_type = {}
            for finding in data:
                t = finding.get("type", "?")
                by_type.setdefault(t, []).append(finding.get("data",""))
            for ftype, items in sorted(by_type.items()):
                out.append(f"\n  {ftype} ({len(items)}):")
                for item in items[:5]:
                    out.append(f"    {str(item)[:120]}")
            return "\n".join(out)
        else:
            return f"[SPIDERFOOT] Scan ran but no output file. stderr: {proc.stderr[:500]}"
    except subprocess.TimeoutExpired:
        return "[SPIDERFOOT] Timed out after 5 minutes — partial results may be in reports/"
    except Exception as e:
        return f"[SPIDERFOOT] Error: {e}"


def tool_file_write_and_ingest(target, content, mode):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M')
    safe = re.sub(r'[^\w\-_\.]', '_', target)
    filename = f"osint_{mode}_{safe}_{ts}.md"
    filepath = REPORTS_DIR / filename
    try:
        filepath.write_text(content, encoding='utf-8')
        cprint(C_TOOL, f"  [FILE] Saved: {filepath}")
        result = f"[FILE_WRITE] Saved: {filepath}"
    except Exception as e:
        return f"[FILE_WRITE] Error: {e}"
    # Auto-ingest to RAG (MySQL)
    try:
        import sys as _sys
        _sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
        from rag_mysql import rag_ingest
        msg = rag_ingest(content, source=filename, doc_id=f"osint_{mode}_{safe}_{ts}_0")
        result += f"\n[RAG] {msg}"
        cprint(C_INFO, f"  [RAG] {msg}")
    except Exception as e:
        result += f"\n[RAG] Skipped: {e}"
    return result


def tool_python_exec(code):
    cprint(C_TOOL, "  [PYTHON] Executing...")
    tmp = Path("/tmp/agent01_v2_exec.py")
    try:
        tmp.write_text(code)
        r = subprocess.run([sys.executable, str(tmp)],
                          capture_output=True, text=True, timeout=60)
        out = r.stdout + r.stderr
        return out[:3000] if out.strip() else "[PYTHON] No output."
    except subprocess.TimeoutExpired:
        return "[PYTHON] Timed out after 60s"
    except Exception as e:
        return f"[PYTHON] Error: {e}"
    finally:
        tmp.unlink(missing_ok=True)


def tool_securitytrails_lookup(target):
    cprint(C_TOOL, f"  [SECURITYTRAILS] {target}")
    if not SECURITYTRAILS_KEY:
        return "[SECURITYTRAILS] No API key — set SECURITYTRAILS_KEY in .env"
    headers = {
        "APIKEY": SECURITYTRAILS_KEY,
        "User-Agent": "AGENTS-HQ/2.0",
        "Accept": "application/json",
    }
    domain = re.sub(r'^https?://', '', target).split('/')[0].strip()
    if '@' in domain:
        domain = domain.split('@')[1]
    out = [f"[SECURITYTRAILS] {domain}:"]
    try:
        # Current DNS records
        r = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}",
                         headers=headers, timeout=TIMEOUT_WEB)
        if r.status_code == 200:
            d = r.json()
            cur = d.get("current_dns", {})
            for rtype in ["a", "aaaa", "mx", "ns", "txt", "soa"]:
                records = cur.get(rtype, {}).get("values", [])
                if records:
                    vals = [rec.get("ip") or rec.get("hostname") or rec.get("value","") for rec in records[:6]]
                    out.append(f"  {rtype.upper()}: {', '.join(str(v) for v in vals if v)}")
            alexa = d.get("alexa_rank")
            if alexa:
                out.append(f"  Alexa rank: {alexa}")
            apex = d.get("apex_domain")
            if apex:
                out.append(f"  Apex domain: {apex}")
        elif r.status_code == 403:
            return "[SECURITYTRAILS] Forbidden — check SECURITYTRAILS_KEY in .env"
        elif r.status_code == 429:
            return "[SECURITYTRAILS] Rate limited (50 req/month free tier)"
        else:
            out.append(f"  DNS lookup status {r.status_code}")

        # Subdomains
        r2 = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                          headers=headers, params={"children_only": "false"},
                          timeout=TIMEOUT_WEB)
        if r2.status_code == 200:
            d2 = r2.json()
            subs = d2.get("subdomains", [])
            total = d2.get("subdomain_count", len(subs))
            out.append(f"\n  Subdomains ({total} total, showing {min(30, len(subs))}):")
            for sub in subs[:30]:
                out.append(f"    {sub}.{domain}")

        # Historical WHOIS
        r3 = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}/whois",
                          headers=headers, timeout=TIMEOUT_WEB)
        if r3.status_code == 200:
            d3 = r3.json()
            items = d3.get("result", {}).get("items", [])
            if items:
                out.append(f"\n  WHOIS history ({len(items)} records):")
                for item in items[:4]:
                    out.append(f"    [{item.get('started','?')} → {item.get('ended','present')}]")
                    contacts = item.get("contacts", [])
                    for c in contacts[:2]:
                        email = c.get("email")
                        org   = c.get("organization")
                        if email: out.append(f"      Email: {email}")
                        if org:   out.append(f"      Org:   {org}")

        return "\n".join(out)
    except Exception as e:
        return f"[SECURITYTRAILS] Error: {e}"


def tool_ipinfo_lookup(target):
    cprint(C_TOOL, f"  [IPINFO] {target}")
    ip = target
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            return f"[IPINFO] Could not resolve {target}"
    headers = {"User-Agent": "AGENTS-HQ/2.0", "Accept": "application/json"}
    if IPINFO_TOKEN:
        headers["Authorization"] = f"Bearer {IPINFO_TOKEN}"
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json",
                         headers=headers, timeout=TIMEOUT_WEB)
        if r.status_code == 200:
            d = r.json()
            out = [f"[IPINFO] {ip}:"]
            out.append(f"  Hostname : {d.get('hostname', 'N/A')}")
            out.append(f"  Org/ASN  : {d.get('org', 'N/A')}")
            out.append(f"  Location : {d.get('city','?')}, {d.get('region','?')}, {d.get('country','?')}")
            out.append(f"  Postal   : {d.get('postal', 'N/A')}")
            out.append(f"  Timezone : {d.get('timezone', 'N/A')}")
            if d.get('loc'):
                lat, lon = d['loc'].split(',')
                out.append(f"  Coords   : {d['loc']}")
                out.append(f"  Maps     : https://maps.google.com/?q={d['loc']}")
            # Privacy fields (premium but attempt anyway)
            privacy = d.get('privacy', {})
            if privacy:
                out.append(f"\n  Privacy Detection:")
                out.append(f"    VPN     : {privacy.get('vpn', 'N/A')}")
                out.append(f"    Proxy   : {privacy.get('proxy', 'N/A')}")
                out.append(f"    Tor     : {privacy.get('tor', 'N/A')}")
                out.append(f"    Hosting : {privacy.get('hosting', 'N/A')}")
            # Abuse contact
            abuse = d.get('abuse', {})
            if abuse:
                out.append(f"\n  Abuse Contact:")
                out.append(f"    Email  : {abuse.get('email', 'N/A')}")
                out.append(f"    Phone  : {abuse.get('phone', 'N/A')}")
                out.append(f"    Network: {abuse.get('network', 'N/A')}")
            # Company info
            company = d.get('company', {})
            if company:
                out.append(f"\n  Company:")
                out.append(f"    Name   : {company.get('name', 'N/A')}")
                out.append(f"    Domain : {company.get('domain', 'N/A')}")
                out.append(f"    Type   : {company.get('type', 'N/A')}")
            return "\n".join(out)
        elif r.status_code == 429:
            return "[IPINFO] Rate limited — 50k/month free tier exceeded"
        else:
            return f"[IPINFO] Status {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return f"[IPINFO] Error: {e}"


def tool_abuseipdb_lookup(target):
    cprint(C_TOOL, f"  [ABUSEIPDB] {target}")
    if not ABUSEIPDB_KEY:
        return "[ABUSEIPDB] No API key — set ABUSEIPDB_KEY in .env"
    ip = target
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            return f"[ABUSEIPDB] Could not resolve {target}"
    try:
        # Check IP reputation
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json",
                     "User-Agent": "AGENTS-HQ/2.0"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=TIMEOUT_WEB)
        if r.status_code == 200:
            d = r.json().get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            score_label = ("🔴 HIGH RISK" if score >= 75
                           else "🟡 SUSPICIOUS" if score >= 25
                           else "🟢 CLEAN")
            out = [f"[ABUSEIPDB] {ip}:"]
            out.append(f"  Abuse Score     : {score}% — {score_label}")
            out.append(f"  Total Reports   : {d.get('totalReports', 0)}")
            out.append(f"  Distinct Users  : {d.get('numDistinctUsers', 0)}")
            out.append(f"  Last Reported   : {d.get('lastReportedAt', 'Never')}")
            out.append(f"  Country         : {d.get('countryCode', 'N/A')}")
            out.append(f"  ISP             : {d.get('isp', 'N/A')}")
            out.append(f"  Domain          : {d.get('domain', 'N/A')}")
            out.append(f"  Usage Type      : {d.get('usageType', 'N/A')}")
            out.append(f"  Whitelisted     : {d.get('isWhitelisted', False)}")
            out.append(f"  Tor Node        : {d.get('isTor', False)}")

            # Attack categories mapping
            cat_map = {
                1:"DNS Compromise", 2:"DNS Poisoning", 3:"Fraud Orders",
                4:"DDoS Attack", 5:"FTP Brute-Force", 6:"Ping of Death",
                7:"Phishing", 8:"Fraud VoIP", 9:"Open Proxy",
                10:"Web Spam", 11:"Email Spam", 12:"Blog Spam",
                13:"VPN IP", 14:"Port Scan", 15:"Hacking",
                16:"SQL Injection", 17:"Spoofing", 18:"Brute-Force",
                19:"Bad Web Bot", 20:"Exploited Host", 21:"Web App Attack",
                22:"SSH", 23:"IoT Targeted"
            }
            reports = d.get("reports", [])
            if reports:
                out.append(f"\n  Recent Reports ({len(reports)} shown):")
                seen_cats = set()
                for rep in reports[:8]:
                    cats = [cat_map.get(c, str(c)) for c in rep.get("categories", [])]
                    seen_cats.update(cats)
                    out.append(f"    [{rep.get('reportedAt','?')[:10]}] "
                               f"Reporter: {rep.get('reporterCountryCode','?')} | "
                               f"Categories: {', '.join(cats)}")
                    comment = rep.get("comment", "")
                    if comment and len(comment) > 10:
                        out.append(f"      Comment: {comment[:200]}")
                if seen_cats:
                    out.append(f"\n  Attack categories observed: {', '.join(sorted(seen_cats))}")
            return "\n".join(out)
        elif r.status_code == 422:
            return f"[ABUSEIPDB] Invalid IP: {ip}"
        elif r.status_code == 429:
            return "[ABUSEIPDB] Rate limited"
        else:
            return f"[ABUSEIPDB] Status {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return f"[ABUSEIPDB] Error: {e}"


# ── Tool registry ─────────────────────────────────────────────
TOOLS = {
    "whois":           tool_whois,
    "dns_lookup":      tool_dns_lookup,
    "cert_search":     tool_cert_search,
    "shodan_lookup":   tool_shodan_lookup,
    "greynoise_lookup":tool_greynoise_lookup,
    "censys_lookup":   tool_censys_lookup,
    "virustotal_lookup":tool_virustotal_lookup,
    "threatfox_lookup":tool_threatfox_lookup,
    "otx_lookup":      tool_otx_lookup,
    "urlscan_lookup":  tool_urlscan_lookup,
    "wayback_lookup":  tool_wayback_lookup,
    "bgp_lookup":      tool_bgp_lookup,
    "reverse_ip":      tool_reverse_ip,
    "asn_lookup":      tool_asn_lookup,
    "email_harvest":   tool_email_harvest,
    "phone_lookup":    tool_phone_lookup,
    "image_intel":     tool_image_intel,
    "web_search":      tool_web_search,
    "spiderfoot_scan": tool_spiderfoot_scan,
    "securitytrails_lookup": tool_securitytrails_lookup,
    "ipinfo_lookup":   tool_ipinfo_lookup,
    "abuseipdb_lookup":tool_abuseipdb_lookup,
    "file_write":      None,   # handled specially
    "python_exec":     tool_python_exec,
}

def dispatch_tool(name, inp, target, mode):
    name = name.strip().lower()
    if name == "file_write":
        return tool_file_write_and_ingest(target, inp, mode)
    if name not in TOOLS:
        return f"[ERROR] Unknown tool '{name}'. Available: {list(TOOLS.keys())}"
    return TOOLS[name](inp.strip())


# ── System Prompt ─────────────────────────────────────────────
def build_system_prompt(target, target_type, mode):
    wf = MODE_WORKFLOWS.get(target_type, MODE_WORKFLOWS["company"]).get(mode, [])
    wf_str = "\n".join([f"  Step {i+1:02d} — {t}" for i, t in enumerate(wf)])

    mode_instructions = {
        "fast":     "FAST RECON MODE: Move quickly. Top findings only. Skip if no data in 1 try.",
        "deep":     "DEEP INTEL MODE: Be thorough. Use all relevant tools. Correlate findings.",
        "adaptive": "ADAPTIVE MODE: Start broad, go deep on interesting findings. Follow leads.",
        "insane":   ("INSANE MODE — SCORCHED EARTH: Use EVERY tool. Follow EVERY lead. "
                    "Correlate ALL findings. Run multiple web_search queries with different "
                    "angles. After all tools complete — reason over all findings and produce "
                    "a comprehensive intelligence dossier with threat assessment, "
                    "attack surface map, and recommended next steps for Agent-02."),
    }

    return f"""You are Agent-01, an autonomous OSINT intelligence agent operating in {mode.upper()} mode.
Target: {target}
Target type: {target_type}
Mode: {mode.upper()} — {MODE_LABELS.get(mode, mode)}

{mode_instructions.get(mode, '')}

AVAILABLE TOOLS (23 total):
  whois, dns_lookup, cert_search, shodan_lookup, greynoise_lookup,
  censys_lookup, virustotal_lookup, threatfox_lookup, otx_lookup,
  urlscan_lookup, wayback_lookup, bgp_lookup, reverse_ip, asn_lookup,
  securitytrails_lookup, ipinfo_lookup, abuseipdb_lookup,
  email_harvest, phone_lookup, image_intel, web_search,
  spiderfoot_scan, file_write, python_exec

WORKFLOW FOR THIS TARGET ({target_type.upper()}, {mode.upper()} mode):
{wf_str}

FORMAT FOR TOOL CALLS:
THOUGHT: <one sentence — what you are doing and why>
ACTION: <tool_name>
INPUT: <input>

WHEN TASK IS COMPLETE:
THOUGHT: <brief summary>
FINAL_ANSWER: <complete intelligence report>

CRITICAL: FINAL_ANSWER is a KEYWORD not a tool.
NEVER write "ACTION: FINAL_ANSWER".

STRICT RULES:
1. ONE THOUGHT + ONE ACTION + ONE INPUT per response
2. Keep thinking to 3-4 sentences max then write action immediately
3. NEVER plan multiple steps ahead
4. If tool returns no data — move to next step immediately, never retry same input
5. STOP after INPUT line or FINAL_ANSWER line
6. For web_search in insane mode — use different angles each time:
   "site:pastebin.com {target}", "inurl:admin {target}", "{target} leaked" etc.
7. The file_write INPUT should be the FULL intelligence report in markdown format"""


# ── LLM ───────────────────────────────────────────────────────
def call_llm(messages):
    url     = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/chat"
    payload = {
        "model":    AGENT_MODEL,
        "messages": messages,
        "stream":   True,
        "think":    False,
        "options":  {"temperature": 0.1, "num_predict": 1024,
                     "num_ctx": 8192, "top_p": 0.9,
                     "stop": ["\nOBSERVATION:", "[Wait", "[After"]}
    }
    try:
        r = requests.post(url, json=payload, stream=True, timeout=180)
        r.raise_for_status()
    except requests.exceptions.ConnectionError:
        cprint(C_WARN, f"[ERROR] Cannot reach ollama at {OLLAMA_HOST}:{OLLAMA_PORT}")
        sys.exit(1)

    full = ""
    thinking_text = ""
    in_think = think_opened = False

    for line in r.iter_lines():
        if not line:
            continue
        data        = json.loads(line)
        msg         = data.get("message", {})
        token       = msg.get("content", "")
        think_token = msg.get("thinking", "")

        if think_token:
            if not think_opened:
                print(f"\n{C_THINK}  ┌─ THINKING {'─'*47}{C_RESET}")
                think_opened = in_think = True
            print(f"{C_THINK}{think_token}{C_RESET}", end="", flush=True)
            thinking_text += think_token

        if token and in_think:
            print(f"\n{C_THINK}  └─ {'─'*53}{C_RESET}\n")
            in_think = False

        if token:
            if not think_opened:
                print(f"\n{C_THINK}  ┌─ THINKING {'─'*47}{C_RESET}")
                print(f"{C_THINK}  [no thinking output]{C_RESET}")
                print(f"{C_THINK}  └─ {'─'*53}{C_RESET}\n")
                think_opened = True
            print(f"{C_ACT}{token}{C_RESET}", end="", flush=True)
            full += token

        if data.get("done"):
            if in_think:
                print(f"\n{C_THINK}  └─ {'─'*53}{C_RESET}\n")
            break

    print()
    return full


# ── Parser ────────────────────────────────────────────────────
def parse_response(response):
    result = {"thought": "", "action": None, "input": None, "final_answer": None}
    clean  = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL).strip()
    clean  = re.sub(r'\[Wait[^\]]*\]|\[After[^\]]*\]', '', clean).strip()
    if not clean:
        cprint(C_WARN, "  [PARSER] Empty content")
        return result

    fa = re.search(r'FINAL_ANSWER:\s*(.*?)$', clean, re.DOTALL | re.IGNORECASE)
    if fa:
        t = re.search(r'THOUGHT:\s*(.*?)(?=FINAL_ANSWER:)', clean, re.DOTALL | re.IGNORECASE)
        result["thought"]      = t.group(1).strip() if t else ""
        result["final_answer"] = fa.group(1).strip()
        return result

    if re.search(r'ACTION:\s*FINAL_ANSWER', clean, re.IGNORECASE):
        inp = re.search(r'INPUT:\s*(.*?)$', clean, re.DOTALL | re.IGNORECASE)
        t   = re.search(r'THOUGHT:\s*(.*?)(?=ACTION:)', clean, re.DOTALL | re.IGNORECASE)
        result["thought"]      = t.group(1).strip() if t else ""
        result["final_answer"] = inp.group(1).strip() if inp else result["thought"]
        cprint(C_WARN, "  [PARSER] Caught 'ACTION: FINAL_ANSWER' — recovered")
        return result

    positions = [m.start() for m in re.finditer(r'^ACTION:', clean, re.MULTILINE | re.IGNORECASE)]
    if len(positions) > 1:
        fb = re.search(
            r'(THOUGHT:.*?ACTION:\s*\w+.*?INPUT:.*?)(?=\nTHOUGHT:|\nACTION:|\nFINAL_ANSWER:|$)',
            clean, re.DOTALL | re.IGNORECASE)
        if fb:
            clean = fb.group(1).strip()
            cprint(C_WARN, "  [PARSER] Multi-step — truncated to first action")

    t = re.search(r'THOUGHT:\s*(.*?)(?=ACTION:|FINAL_ANSWER:)', clean, re.DOTALL | re.IGNORECASE)
    a = re.search(r'ACTION:\s*(\w+)', clean, re.IGNORECASE)
    i = re.search(r'INPUT:\s*(.*?)(?=\nTHOUGHT:|\nACTION:|\nFINAL_ANSWER:|\nOBSERVATION:|$)',
                  clean, re.DOTALL | re.IGNORECASE)
    if t: result["thought"] = t.group(1).strip()
    if a: result["action"]  = a.group(1).strip()
    if i: result["input"]   = i.group(1).strip()
    return result


# ── ReAct Loop ────────────────────────────────────────────────
def react_loop(target, target_type, mode, image_path=None):
    mc = MODE_COLORS.get(mode, C_HEAD)
    cprint(mc,   f"\n{'='*65}")
    cprint(mc,   f"  AGENT-01 OSINT v2  |  {AGENT_MODEL}")
    cprint(mc,   f"  Target : {target}  [{target_type.upper()}]")
    cprint(mc,   f"  Mode   : {MODE_LABELS.get(mode, mode)}")
    cprint(mc,   f"  Steps  : max {MODE_LIMITS.get(mode, 25)}")
    if image_path:
        cprint(mc, f"  Image  : {image_path}")

    # API key status
    keys = {"Shodan":SHODAN_API_KEY, "GreyNoise":GREYNOISE_KEY,
            "Censys":CENSYS_TOKEN, "VirusTotal":VIRUSTOTAL_KEY,
            "HIBP":HIBP_API_KEY, "Hunter":HUNTER_KEY,
            "OTX":OTX_KEY, "urlscan":URLSCAN_KEY,
            "SecurityTrails":SECURITYTRAILS_KEY,
            "IPinfo":IPINFO_TOKEN, "AbuseIPDB":ABUSEIPDB_KEY}
    active = [k for k,v in keys.items() if v]
    missing = [k for k,v in keys.items() if not v]
    cprint(C_INFO,  f"  Keys   : {', '.join(active) if active else 'none'}")
    if missing:
        cprint(C_WARN, f"  Missing: {', '.join(missing)}")
    cprint(mc, f"{'='*65}\n")

    system = build_system_prompt(target, target_type, mode)
    wf     = MODE_WORKFLOWS.get(target_type, MODE_WORKFLOWS["company"]).get(mode, [])

    first_msg = (f"TARGET: {target}\nTYPE: {target_type}\nMODE: {mode}\n\n")
    if image_path:
        first_msg += f"IMAGE: {image_path}\nStart with image_intel.\n\n"
    first_msg += f"Begin OSINT collection. Execute step 1 now.{FORMAT_REMINDER}"

    messages       = [{"role": "system", "content": system},
                      {"role": "user",   "content": first_msg}]
    final_answer   = None
    iteration      = 0
    action_history = []
    max_iter       = MODE_LIMITS.get(mode, 25)

    while iteration < max_iter:
        iteration += 1
        cprint(mc, f"\n{'-'*65}")
        cprint(mc, f"  Step {iteration}/{max_iter}  [{mode.upper()}]")
        cprint(mc, f"{'-'*65}")

        response = call_llm(messages)
        parsed   = parse_response(response)
        messages.append({"role": "assistant", "content": response})

        if parsed["final_answer"]:
            final_answer = parsed["final_answer"]
            cprint(mc, f"\n{'='*65}")
            cprint(mc, f"  COMPLETE — {iteration} steps  [{mode.upper()}]")
            cprint(mc, f"{'='*65}")
            break

        if parsed["action"] and parsed["input"]:
            key = f"{parsed['action']}::{parsed['input'][:120]}"
            if action_history.count(key) >= 2:
                used   = set(h.split("::")[0] for h in action_history)
                unused = [x for x in wf if x not in used]
                cprint(C_WARN, f"  [LOOP] Repeated action — forcing next step")
                messages.append({"role": "user", "content":
                    f"You ran {parsed['action']} with same input twice. STOP.\n"
                    f"Remaining workflow steps: {unused}\n"
                    f"Move to next step.{FORMAT_REMINDER}"})
                continue

            action_history.append(key)
            cprint(C_TOOL, f"\n  -> {parsed['action']}")
            observation = dispatch_tool(parsed["action"], parsed["input"], target, mode)
            preview = observation[:800] + ("..." if len(observation) > 800 else "")
            cprint(C_OBS, f"\n  [OBSERVATION]\n{preview}")

            # Next step hint
            steps_done = set(h.split("::")[0] for h in action_history)
            next_hint  = ""
            for step in wf:
                if step not in steps_done:
                    next_hint = f"\nNEXT STEP: {step}"
                    break
            if not next_hint and mode == "insane":
                next_hint = "\nAll workflow steps done. Write FINAL_ANSWER with full dossier."

            messages.append({"role": "user", "content":
                f"OBSERVATION from {parsed['action']}:\n{observation}"
                f"{next_hint}{FORMAT_REMINDER}"})
        else:
            cprint(C_WARN, "  [PARSER] No action — nudging")
            messages.append({"role": "user", "content":
                f"STOP THINKING. Output action NOW:\n"
                f"THOUGHT: <one sentence>\nACTION: <tool>\nINPUT: <input>\n"
                f"Workflow remaining: {[s for s in wf if s not in set(h.split('::')[0] for h in action_history)]}"})

    if not final_answer:
        final_answer = f"Max iterations ({max_iter}) reached. Reports in: {REPORTS_DIR}"
        cprint(C_WARN, "\n[!] Max iterations reached.")

    return final_answer


# ── n8n Webhook Server ────────────────────────────────────────
def run_webhook_server():
    from http.server import HTTPServer, BaseHTTPRequestHandler
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                try:
                    self.wfile.write(b'{"status":"ok","agent":"01"}')
                except BrokenPipeError:
                    pass
            else:
                self.send_response(404)
                self.end_headers()
        def do_POST(self):
            if self.path == "/webhook/agent01":
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                try:
                    data        = json.loads(body)
                    target      = data.get("target", "")
                    target_type = data.get("type", detect_target_type(target)) if target else "image"
                    mode        = data.get("mode", "adaptive")
                    image_path  = data.get("image", None)
                    if not target and image_path:
                        target = image_path
                    if mode not in MODE_LIMITS:
                        mode = "adaptive"
                    cprint(C_HEAD, f"\n[WEBHOOK] {target} [{target_type}] mode:{mode}")
                    result = react_loop(target, target_type, mode, image_path)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"status":"complete","result":result,"mode":mode}).encode())
                except Exception as e:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": str(e)}).encode())
            else:
                self.send_response(404)
                self.end_headers()
        def log_message(self, fmt, *args):
            cprint(C_INFO, f"  [HTTP] {fmt % args}")

    cprint(C_HEAD, f"\n{'='*65}")
    cprint(C_HEAD, f"  AGENT-01 OSINT v2 — Webhook Server")
    cprint(C_HEAD, f"  Listening: 127.0.0.1:{N8N_WEBHOOK_PORT}")
    cprint(C_HEAD, f"  Endpoint: POST /webhook/agent01")
    cprint(C_HEAD, f"  Body: {{\"target\":\"example.com\",\"type\":\"domain\",\"mode\":\"deep\"}}")
    cprint(C_HEAD, f"  Modes: fast | deep | adaptive | insane")
    cprint(C_HEAD, f"{'='*65}\n")
    HTTPServer(("127.0.0.1", N8N_WEBHOOK_PORT), Handler).serve_forever()


# ── Main ──────────────────────────────────────────────────────
def main():
    load_env()
    global SHODAN_API_KEY, GREYNOISE_KEY, CENSYS_TOKEN
    global VIRUSTOTAL_KEY, HIBP_API_KEY, NUMVERIFY_KEY, HUNTER_KEY
    global URLSCAN_KEY, OTX_KEY, SECURITYTRAILS_KEY, IPINFO_TOKEN, ABUSEIPDB_KEY
    SHODAN_API_KEY     = os.environ.get("SHODAN_API_KEY", "")
    GREYNOISE_KEY      = os.environ.get("GREYNOISE_API_KEY", "")
    CENSYS_TOKEN       = os.environ.get("CENSYS_API_TOKEN", "")
    VIRUSTOTAL_KEY     = os.environ.get("VIRUSTOTAL_API_KEY", "")
    HIBP_API_KEY       = os.environ.get("HIBP_API_KEY", "")
    NUMVERIFY_KEY      = os.environ.get("NUMVERIFY_KEY", "")
    HUNTER_KEY         = os.environ.get("HUNTER_API_KEY", "")
    URLSCAN_KEY        = os.environ.get("URLSCAN_API_KEY", "")
    OTX_KEY            = os.environ.get("OTX_API_KEY", "")
    SECURITYTRAILS_KEY = os.environ.get("SECURITYTRAILS_KEY", "")
    IPINFO_TOKEN       = os.environ.get("IPINFO_TOKEN", "")
    ABUSEIPDB_KEY      = os.environ.get("ABUSEIPDB_KEY", "")

    parser = argparse.ArgumentParser(
        description="Agent-01 OSINT v2 — Full-spectrum intelligence platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Modes:
  fast     — 15 steps  — quick triage
  deep     — 25 steps  — full surface map
  adaptive — 30 steps  — auto-scaled depth
  insane   — 60 steps  — scorched earth dossier

Examples:
  python3 agent_01_osint_v2.py --target example.com --mode fast
  python3 agent_01_osint_v2.py --target 8.8.8.8 --mode deep
  python3 agent_01_osint_v2.py --target user@corp.com --mode adaptive
  python3 agent_01_osint_v2.py --target "Acme Corp" --mode insane
  python3 agent_01_osint_v2.py --target +306912345678 --mode fast
  python3 agent_01_osint_v2.py --image photo.jpg --mode deep
  python3 agent_01_osint_v2.py --n8n-server

.env keys (agent_01_osint/.env):
  SHODAN_API_KEY       shodan.io
  GREYNOISE_API_KEY    greynoise.io
  CENSYS_API_TOKEN     censys.io (Personal Access Token)
  VIRUSTOTAL_API_KEY   virustotal.com
  URLSCAN_API_KEY      urlscan.io
  OTX_API_KEY          otx.alienvault.com
  SECURITYTRAILS_KEY   securitytrails.com
  IPINFO_TOKEN         ipinfo.io
  ABUSEIPDB_KEY        abuseipdb.com
  HIBP_API_KEY         haveibeenpwned.com (optional, paid)
        """)
    parser.add_argument("--target","-t",  help="Target: domain/IP/email/company/phone")
    parser.add_argument("--image", "-i",  help="Image file for EXIF/GPS analysis")
    parser.add_argument("--mode",  "-m",  default="adaptive",
                        choices=["fast","deep","adaptive","insane"])
    parser.add_argument("--type",         help="Force type: domain/ip/email/phone/company/image")
    parser.add_argument("--interactive","-I", action="store_true")
    parser.add_argument("--n8n-server",   action="store_true")
    args = parser.parse_args()

    if args.n8n_server:
        run_webhook_server()
        return

    target      = args.target
    mode        = args.mode
    target_type = args.type
    image_path  = args.image

    if args.interactive:
        print(f"\n{C_HEAD}AGENT-01 OSINT v2 — Interactive Mode{C_RESET}")
        print("Enter target or 'image' for photo analysis:")
        user_input = input("> ").strip()
        if user_input.lower() == "image":
            image_path = input("Image file path: ").strip()
            target = image_path
            target_type = "image"
        else:
            target = user_input
        print("Mode [fast/deep/adaptive/insane] (default: adaptive): ", end="")
        m = input().strip().lower()
        if m in MODE_LIMITS:
            mode = m
    elif image_path and not target:
        target      = image_path
        target_type = "image"
    elif not target:
        parser.print_help()
        sys.exit(0)

    if not target_type:
        target_type = "image" if image_path else detect_target_type(target)

    result = react_loop(target, target_type, mode, image_path)

    cprint(MODE_COLORS.get(mode, C_HEAD),
           f"\n{'='*65}\nINTELLIGENCE REPORT [{mode.upper()}]:\n{'='*65}")
    print(result)


if __name__ == "__main__":
    main()
