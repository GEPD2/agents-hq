#!/usr/bin/env python3
"""
AGENTS-HQ — Agent-04 Orchestrator v1
Master controller — every task enters here first

Routing Matrix:
  IP          →  Agent-01 OSINT  →  Agent-02 Recon  →  Agent-03 RAG (CVEs)
  Domain      →  Agent-01 OSINT  →  Agent-02 Recon  →  Agent-03 RAG (CVEs)
  Email       →  Agent-01 OSINT
  Phone       →  Agent-01 OSINT
  Company     →  Agent-01 OSINT
  Hash        →  Agent-01 OSINT (VT)  →  Agent-06 Ghidra
  File/Binary →  Agent-06 Ghidra  →  Agent-01 OSINT (IOCs)  →  Agent-03 RAG
  CVE ID      →  Agent-03 RAG  →  Agent-02 (NVD search)
  Free text   →  Agent-02 Task

Modes:
  --mode fast   Agent-01 fast only — quick triage, one agent
  --mode deep   Full pipeline, all relevant agents
  --mode auto   (default) smart depth based on target type

Usage:
  python3 agent_04_orchestrator.py --target 93.184.216.34
  python3 agent_04_orchestrator.py --target evil.exe --mode deep
  python3 agent_04_orchestrator.py --target CVE-2024-21413
  python3 agent_04_orchestrator.py --task "enumerate subdomains of tesla.com"
  python3 agent_04_orchestrator.py --interactive
  python3 agent_04_orchestrator.py --n8n-server
"""

import sys, json, subprocess, argparse, re, os, time, threading
from datetime import datetime
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent.parent
REPORTS_DIR = BASE_DIR / "reports"
A01_DIR     = BASE_DIR / "agent_01_osint"
A02_DIR     = BASE_DIR / "agent_02_task"
A03_DIR     = BASE_DIR / "agent_03_rag"
A06_DIR     = BASE_DIR / "agent_06_ghidra"

A01_SCRIPT  = A01_DIR / "agent_01_osint_v3.py"
A02_SCRIPT  = A02_DIR / "agent.py"
A03_SCRIPT  = A03_DIR / "query.py"
A06_SCRIPT  = A06_DIR / "agent_06_ghidra.py"

# ── Config ─────────────────────────────────────────────────────
N8N_WEBHOOK_PORT = int(os.environ.get("N8N_WEBHOOK_PORT", "8764"))
AGENT_TIMEOUT    = 600   # 10 min max per agent

# ── ANSI Colors ────────────────────────────────────────────────
C_HEAD  = "\033[38;5;201m"   # magenta  — orchestrator identity
C_AGENT = "\033[38;5;39m"    # blue     — agent call headers
C_OK    = "\033[38;5;82m"    # green    — success
C_WARN  = "\033[38;5;196m"   # red      — errors / warnings
C_INFO  = "\033[38;5;226m"   # yellow   — informational
C_DIM   = "\033[38;5;244m"   # grey     — subprocess output passthrough
C_RESET = "\033[0m"

ANSI_RE = re.compile(r'\033\[[0-9;]*m')

def cprint(color, text, end="\n"):
    print(f"{color}{text}{C_RESET}", end=end, flush=True)

def strip_ansi(text: str) -> str:
    return ANSI_RE.sub('', text)


# ── Input Validation ───────────────────────────────────────────
_SAFE_TARGET_RE = re.compile(r'^[A-Za-z0-9 ./:_@?=&%+,\-\[\]{}#!*]+$')
_TARGET_MAX_LEN = 512

def validate_target(target: str) -> str:
    t = target.strip()
    if not t:
        raise ValueError("target is empty")
    if len(t) > _TARGET_MAX_LEN:
        raise ValueError(f"target exceeds {_TARGET_MAX_LEN} characters")
    if any(c in t for c in ("\x00", "\n", "\r")):
        raise ValueError("target contains invalid characters")
    if not _SAFE_TARGET_RE.match(t):
        raise ValueError(f"target contains disallowed characters: {t!r}")
    return t


# ── Python Finder ──────────────────────────────────────────────
def find_python(agent_dir: Path, fallback_dir: Path = None) -> str:
    """Return the venv Python for an agent, or fall back to system Python."""
    for d in ([agent_dir] + ([fallback_dir] if fallback_dir else [])):
        for name in ("venv", ".venv"):
            p = d / name / "bin" / "python3"
            if p.exists():
                return str(p)
    return sys.executable


# ── Target Type Detection ──────────────────────────────────────
def detect_type(target: str) -> str:
    t = target.strip()
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', t):
        return "ip"
    if re.match(r'^[0-9a-fA-F]{64}$', t):
        return "hash_sha256"
    if re.match(r'^[0-9a-fA-F]{40}$', t):
        return "hash_sha1"
    if re.match(r'^[0-9a-fA-F]{32}$', t):
        return "hash_md5"
    if re.match(r'^CVE-\d{4}-\d+$', t, re.IGNORECASE):
        return "cve"
    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', t):
        return "email"
    if re.match(r'^\+?\d[\d\s\-]{7,15}$', t):
        return "phone"
    if Path(t).exists() and Path(t).is_file():
        return "file"
    if re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', t):
        return "domain"
    # multi-word or title-case → treat as company/org name
    if ' ' in t or (t[0].isupper() and not re.search(r'[.\-]', t)):
        return "company"
    return "domain"   # safe fallback


# ── Agent Runner ───────────────────────────────────────────────
def run_agent(label: str, cmd: list, cwd: Path,
              timeout: int = AGENT_TIMEOUT) -> tuple[bool, str]:
    bar = "─" * max(1, 56 - len(label))
    cprint(C_AGENT, f"\n  ┌─ {label} {bar}")
    cprint(C_AGENT, f"  │  {' '.join(str(c) for c in cmd)}")
    cprint(C_AGENT, f"  └{'─'*59}")

    if not Path(cmd[1]).exists():
        cprint(C_WARN, f"  [!] Script not found: {cmd[1]} — skipping")
        return False, f"[SKIP] {cmd[1]} not found"

    output_lines: list[str] = []

    try:
        proc = subprocess.Popen(
            [str(c) for c in cmd],
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        def _stream():
            for line in proc.stdout:
                clean = strip_ansi(line)
                print(f"{C_DIM}  {clean.rstrip()}{C_RESET}", flush=True)
                output_lines.append(clean)

        t = threading.Thread(target=_stream, daemon=True)
        t.start()
        proc.wait(timeout=timeout)
        t.join(timeout=5)

        ok = proc.returncode == 0
        cprint(C_OK if ok else C_WARN,
               f"  [{'✓' if ok else '!'}] {label} exited rc={proc.returncode}")
        return ok, "".join(output_lines)

    except subprocess.TimeoutExpired:
        proc.kill()
        t.join(timeout=2)
        cprint(C_WARN, f"  [!] {label} killed — exceeded {timeout}s")
        return False, "".join(output_lines) + f"\n[TIMEOUT after {timeout}s]"

    except Exception as e:
        cprint(C_WARN, f"  [!] {label} error: {e}")
        return False, f"[ERROR] {e}"


# ── Latest Report Finder ───────────────────────────────────────
def latest_report(since_ts: float, prefix: str = "") -> Path | None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    candidates = [
        f for f in REPORTS_DIR.glob(f"{prefix}*.md")
        if f.stat().st_mtime > since_ts
    ]
    return max(candidates, key=lambda f: f.stat().st_mtime) if candidates else None


# ── Findings Extractor ─────────────────────────────────────────
_PRIVATE = re.compile(r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)')

def extract_ips(text: str) -> list[str]:
    raw = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)
    return list({ip for ip in raw if not _PRIVATE.match(ip)})[:15]

def extract_cves(text: str) -> list[str]:
    return list({m.upper() for m in re.findall(r'CVE-\d{4}-\d+', text, re.IGNORECASE)})[:15]

def extract_domains(text: str) -> list[str]:
    raw   = re.findall(r'\b([a-zA-Z0-9][\w\-]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b', text)
    noise = {'example.com', 'localhost', 'github.com', 'python.org',
             'nvd.nist.gov', 'exploit-db.com', 'virustotal.com'}
    return list({d.lower() for d in raw if d.lower() not in noise})[:15]

def extract_hashes(text: str) -> dict:
    return {
        "sha256": list(set(re.findall(r'\b[0-9a-fA-F]{64}\b', text)))[:5],
        "md5":    list(set(re.findall(r'\b[0-9a-fA-F]{32}\b', text)))[:5],
    }


# ── Master Report Writer ───────────────────────────────────────
def write_master_report(target: str, target_type: str, mode: str,
                         pipeline: list[dict], findings: dict, ts: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    safe  = re.sub(r'[^\w\-_]', '_', target)[:40]
    path  = REPORTS_DIR / f"MASTER_{safe}_{ts}.md"

    lines = [
        "# AGENTS-HQ — Master Intelligence Report",
        f"",
        f"| Field   | Value |",
        f"|---------|-------|",
        f"| Target  | `{target}` |",
        f"| Type    | {target_type} |",
        f"| Mode    | {mode} |",
        f"| Generated | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |",
        f"| Orchestrator | Agent-04 v1 |",
        "",
        "---",
        "",
        "## Pipeline Executed",
        "",
    ]

    for step in pipeline:
        icon = "✅" if step.get("success") else "❌"
        lines.append(f"- {icon} **{step['agent']}** — {step.get('note', '')}")

    lines += ["", "---", "", "## Key Findings", ""]

    if findings.get("ips"):
        lines.append(f"**IPs discovered ({len(findings['ips'])}):** "
                     f"{', '.join(f'`{ip}`' for ip in findings['ips'][:10])}")
    if findings.get("cves"):
        lines.append(f"**CVEs found ({len(findings['cves'])}):** "
                     f"{', '.join(f'`{c}`' for c in findings['cves'])}")
    if findings.get("domains"):
        lines.append(f"**Domains ({len(findings['domains'])}):** "
                     f"{', '.join(f'`{d}`' for d in findings['domains'][:8])}")
    if findings.get("hashes", {}).get("sha256"):
        lines.append(f"**SHA256:** {', '.join(f'`{h}`' for h in findings['hashes']['sha256'])}")

    lines += ["", "---", "", "## Agent Reports", ""]

    for step in pipeline:
        lines += [f"### {step['agent']}", ""]
        if step.get("report"):
            lines.append(f"*Full report: `{step['report']}`*")
        if step.get("summary"):
            lines += ["```", step["summary"][:1200].strip(), "```"]
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# ── Pipeline Router ────────────────────────────────────────────
def run_pipeline(target: str, target_type: str, mode: str) -> str:
    target = validate_target(target)
    ts       = datetime.now().strftime('%Y%m%d_%H%M%S')
    pipeline: list[dict] = []
    findings = {"ips": [], "cves": [], "domains": [], "hashes": {}}

    a01_py = find_python(A01_DIR)
    a02_py = find_python(A02_DIR)
    a03_py = find_python(A03_DIR, A02_DIR)   # no dedicated venv — fall back to agent_02
    a06_py = find_python(A06_DIR)

    cprint(C_HEAD, f"\n{'═'*62}")
    cprint(C_HEAD,  "  AGENT-04 — ORCHESTRATOR")
    cprint(C_HEAD, f"  Target : {target}")
    cprint(C_HEAD, f"  Type   : {target_type}  |  Mode : {mode}")
    cprint(C_HEAD, f"{'═'*62}")

    # ── Helper: run Agent-01 and collect findings ──────────────
    def _run_a01(tgt, a01_mode, ttype=None, label_suffix=""):
        extra = ["--type", ttype] if ttype else []
        t0 = time.time()
        ok, out = run_agent(
            f"Agent-01 OSINT{label_suffix}",
            [a01_py, A01_SCRIPT, "--target", tgt, "--mode", a01_mode] + extra,
            A01_DIR,
        )
        rpt = latest_report(t0, "osint_")
        text = (rpt.read_text() if rpt else out)
        findings["ips"]     += extract_ips(text)
        findings["cves"]    += extract_cves(text)
        findings["domains"] += extract_domains(text)
        pipeline.append({
            "agent":   f"Agent-01 OSINT{label_suffix}",
            "success": ok,
            "note":    f"target={tgt} mode={a01_mode}",
            "report":  str(rpt) if rpt else "",
            "summary": text[:1200],
        })
        return ok, text

    # ── Helper: run Agent-02 recon ─────────────────────────────
    def _run_a02_recon(tgt, label_suffix=""):
        t0 = time.time()
        ok, out = run_agent(
            f"Agent-02 Recon{label_suffix}",
            [a02_py, A02_SCRIPT, "--target", tgt],
            A02_DIR,
        )
        rpt = latest_report(t0, "recon_")
        text = (rpt.read_text() if rpt else out)
        findings["cves"] += extract_cves(text)
        pipeline.append({
            "agent":   f"Agent-02 Recon{label_suffix}",
            "success": ok,
            "note":    f"nmap+CVE on {tgt}",
            "report":  str(rpt) if rpt else "",
            "summary": text[:1200],
        })
        return ok, text

    # ── Helper: run Agent-03 RAG ───────────────────────────────
    def _run_a03(query, note=""):
        if not A03_SCRIPT.exists():
            cprint(C_WARN, "  [!] Agent-03 script not found — skipping RAG")
            return False, ""
        t0 = time.time()
        ok, out = run_agent(
            "Agent-03 RAG",
            [a03_py, A03_SCRIPT, query],
            A03_DIR,
        )
        pipeline.append({
            "agent":   "Agent-03 RAG",
            "success": ok,
            "note":    note or query[:60],
            "summary": out[:1200],
        })
        return ok, out

    # ── Helper: run Agent-06 Ghidra ────────────────────────────
    def _run_a06(tgt, a06_mode, use_hash=False):
        flag = "--hash" if use_hash else "--target"
        t0 = time.time()
        ok, out = run_agent(
            "Agent-06 Ghidra",
            [a06_py, A06_SCRIPT, flag, tgt, "--mode", a06_mode],
            A06_DIR,
        )
        rpt = latest_report(t0, "re_")
        text = (rpt.read_text() if rpt else out)
        findings["cves"]    += extract_cves(text)
        findings["ips"]     += extract_ips(text)
        findings["domains"] += extract_domains(text)
        h = extract_hashes(text)
        findings["hashes"].setdefault("sha256", [])
        findings["hashes"]["sha256"] += h.get("sha256", [])
        pipeline.append({
            "agent":   "Agent-06 Ghidra",
            "success": ok,
            "note":    f"{'hash' if use_hash else 'file'} mode={a06_mode}",
            "report":  str(rpt) if rpt else "",
            "summary": text[:1200],
        })
        return ok, text

    # ──────────────────────────────────────────────────────────
    #  ROUTING
    # ──────────────────────────────────────────────────────────

    if target_type in ("ip", "domain"):
        a01_mode = "fast" if mode == "fast" else "deep"
        _run_a01(target, a01_mode)

        if mode != "fast":
            _run_a02_recon(target)

            cves = list(set(findings["cves"]))
            if cves:
                _run_a03(
                    f"Explain vulnerabilities for: {', '.join(cves[:4])}",
                    note=f"CVE context: {', '.join(cves[:4])}"
                )

    elif target_type in ("email", "phone", "company"):
        a01_mode = "fast" if mode == "fast" else "adaptive"
        _run_a01(target, a01_mode, ttype=target_type)

    elif target_type in ("hash_sha256", "hash_sha1", "hash_md5"):
        _run_a01(target, "fast" if mode == "fast" else "deep")

        if mode != "fast":
            _run_a06(target, "fast", use_hash=True)

            cves = list(set(findings["cves"]))
            if cves:
                _run_a03(
                    f"Malware/CVE context for: {', '.join(cves[:3])}",
                    note="hash RE CVE context"
                )

    elif target_type == "file":
        a06_mode = "fast" if mode == "fast" else "deep"
        _, a06_text = _run_a06(target, a06_mode)

        if mode != "fast":
            iocs = list(set(extract_ips(a06_text) + extract_domains(a06_text)))
            for ioc in iocs[:3]:
                itype = "ip" if re.match(r'^\d{1,3}\.\d{1,3}', ioc) else "domain"
                _run_a01(ioc, "fast", ttype=itype, label_suffix=f" ({ioc})")

            cves = list(set(findings["cves"]))
            if cves:
                _run_a03(
                    f"Malware analysis context for: {', '.join(cves[:3])}",
                    note="file RE CVE context"
                )

    elif target_type == "cve":
        _run_a03(
            f"What is {target}? CVSS score, affected versions, attack vector, PoC.",
            note=f"KB lookup: {target}"
        )
        # Task agent for NVD lookup regardless of mode
        t0 = time.time()
        ok, out = run_agent(
            "Agent-02 Task (NVD)",
            [a02_py, A02_SCRIPT,
             f"Search NVD and provide full details for {target}: "
             f"CVSS score, affected products, available PoC exploits."],
            A02_DIR,
        )
        rpt = latest_report(t0)
        text = (rpt.read_text() if rpt else out)
        findings["cves"].append(target.upper())
        pipeline.append({
            "agent":   "Agent-02 Task (NVD)",
            "success": ok,
            "note":    f"NVD: {target}",
            "report":  str(rpt) if rpt else "",
            "summary": text[:1200],
        })

    else:
        # Free text / unknown — send straight to Agent-02
        t0 = time.time()
        ok, out = run_agent(
            "Agent-02 Task",
            [a02_py, A02_SCRIPT, target],
            A02_DIR,
        )
        rpt = latest_report(t0)
        text = (rpt.read_text() if rpt else out)
        pipeline.append({
            "agent":   "Agent-02 Task",
            "success": ok,
            "note":    "free-text task",
            "report":  str(rpt) if rpt else "",
            "summary": text[:1200],
        })

    # ── De-duplicate findings ──────────────────────────────────
    findings["ips"]     = list(set(findings["ips"]))
    findings["cves"]    = list(set(findings["cves"]))
    findings["domains"] = list(set(findings["domains"]))

    # ── Write master report ────────────────────────────────────
    master = write_master_report(target, target_type, mode, pipeline, findings, ts)

    cprint(C_HEAD, f"\n{'═'*62}")
    cprint(C_HEAD,  "  ORCHESTRATION COMPLETE")
    cprint(C_OK,   f"  Agents run    : {len(pipeline)}")
    cprint(C_OK,   f"  IPs found     : {len(findings['ips'])}")
    cprint(C_OK,   f"  CVEs found    : {len(findings['cves'])}")
    cprint(C_OK,   f"  Domains found : {len(findings['domains'])}")
    cprint(C_OK,   f"  Master report : reports/{master.name}")
    cprint(C_HEAD, f"{'═'*62}\n")

    return master.read_text()


# ── n8n Webhook Server ─────────────────────────────────────────
def run_webhook_server():
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                try:
                    self.wfile.write(b'{"status":"ok","agent":"04"}')
                except BrokenPipeError:
                    pass
            else:
                self.send_response(404)
                self.end_headers()
        def do_POST(self):
            if self.path == "/webhook/agent04":
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                try:
                    data   = json.loads(body)
                    target = validate_target(data.get("target", ""))
                    mode   = data.get("mode", "auto")
                    ttype  = data.get("type") or detect_type(target)
                    if mode not in ("fast", "deep", "auto"):
                        mode = "auto"
                    cprint(C_HEAD,
                           f"\n[WEBHOOK] target={target}  type={ttype}  mode={mode}")
                    result = run_pipeline(target, ttype, mode)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "status": "complete",
                        "target": target,
                        "type":   ttype,
                        "mode":   mode,
                        "result": result,
                    }).encode())
                except Exception as e:
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": str(e)}).encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, fmt, *args):
            cprint(C_INFO, f"  [HTTP] {fmt % args}")

    cprint(C_HEAD, f"\n{'═'*62}")
    cprint(C_HEAD,  "  AGENT-04 ORCHESTRATOR — Webhook Server")
    cprint(C_HEAD, f"  Listening : 127.0.0.1:{N8N_WEBHOOK_PORT}")
    cprint(C_HEAD,  "  Endpoint  : POST /webhook/agent04")
    cprint(C_HEAD,  '  Body      : {"target":"1.2.3.4","mode":"auto"}')
    cprint(C_HEAD,  "  Modes     : fast | deep | auto")
    cprint(C_HEAD, f"{'═'*62}\n")
    HTTPServer(("127.0.0.1", N8N_WEBHOOK_PORT), Handler).serve_forever()


# ── Main ───────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Agent-04 Orchestrator — master controller for all AGENTS-HQ agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Modes:
  fast   Agent-01 fast only — quick triage
  deep   Full pipeline — all relevant agents run
  auto   (default) smart depth based on target type

Examples:
  python3 agent_04_orchestrator.py --target 93.184.216.34
  python3 agent_04_orchestrator.py --target example.com --mode deep
  python3 agent_04_orchestrator.py --target malware.exe --mode deep
  python3 agent_04_orchestrator.py --target CVE-2024-21413
  python3 agent_04_orchestrator.py --target d41d8cd98f00b204e9800998ecf8427e
  python3 agent_04_orchestrator.py --target user@corp.com
  python3 agent_04_orchestrator.py --task "find all subdomains of tesla.com"
  python3 agent_04_orchestrator.py --n8n-server
        """,
    )
    parser.add_argument("--target", "-t",
                        help="Target: IP / domain / email / phone / company / hash / file / CVE")
    parser.add_argument("--task",   "-k",
                        help="Free-text task (routed to Agent-02)")
    parser.add_argument("--type",
                        help="Force type: ip / domain / email / phone / company / "
                             "hash_sha256 / hash_md5 / file / cve")
    parser.add_argument("--mode",   "-m", default="auto",
                        choices=["fast", "deep", "auto"])
    parser.add_argument("--interactive", "-i", action="store_true")
    parser.add_argument("--n8n-server",        action="store_true")
    args = parser.parse_args()

    if args.n8n_server:
        run_webhook_server()
        return

    if args.interactive:
        cprint(C_HEAD, "\nAGENT-04 ORCHESTRATOR — Interactive Mode")
        print("Target (IP / domain / email / hash / file / CVE / task): ", end="")
        raw = input().strip()
        if not raw:
            sys.exit(0)
        print("Mode [fast / deep / auto] (default: auto): ", end="")
        m = input().strip().lower()
        args.target = raw
        args.mode   = m if m in ("fast", "deep", "auto") else "auto"

    # --task is sugar for a free-text target
    if args.task and not args.target:
        args.target = args.task
        args.type   = args.type or "unknown"

    if not args.target:
        parser.print_help()
        sys.exit(0)

    ttype = args.type or detect_type(args.target)

    result = run_pipeline(args.target, ttype, args.mode)
    # Print just the findings table from the master report
    print(result[:3000])


if __name__ == "__main__":
    main()
