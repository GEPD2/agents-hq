#!/usr/bin/env python3
"""
AGENTS-HQ — Agent-05 Red Team v1
Adversarial intelligence and exploitation agent

Two phases, always in this order:
  PHASE 1 — ADVISORY  (always runs)
    Full attack surface analysis, kill chain, MITRE ATT&CK mapping,
    CVE-to-exploit correlation, tooling recommendations.
    No execution. No risk. Pure intelligence.

  PHASE 2 — ACTIVE    (only with --mode active, requires --execute flag)
    Executes the attack plan step by step in a ReAct loop.
    !! EVERY offensive action requires explicit human approval !!
    The LLM proposes. The human decides. No exceptions.
    Approval gate is enforced in Python — the model cannot bypass it.

Input sources:
  --target      IP / domain / CIDR — agent does its own recon context
  --report      Path to an Agent-04 MASTER report — skips recon, uses existing findings
  --task        Free-text engagement description

Modes:
  --mode advisory   Phase 1 only (default)
  --mode active     Phase 1 + Phase 2, human gates on every attack step
                    Requires --execute flag as second confirmation

Usage:
  python3 agent_05_redteam.py --target 192.168.1.10 --mode advisory
  python3 agent_05_redteam.py --target 192.168.1.10 --mode active --execute
  python3 agent_05_redteam.py --report reports/MASTER_192_168_1_10_*.md --mode active --execute
  python3 agent_05_redteam.py --interactive
  python3 agent_05_redteam.py --n8n-server
"""

import sys, json, subprocess, argparse, re, os, time
from datetime import datetime
from pathlib import Path

# ── Config ─────────────────────────────────────────────────────
OLLAMA_HOST      = "localhost"
OLLAMA_PORT      = 11434
AGENT_MODEL      = "deepseek-r1:8b"
CHROMA_HOST      = "localhost"
CHROMA_PORT      = 8000
REPORTS_DIR      = Path(__file__).parent.parent / "reports"
N8N_WEBHOOK_PORT = int(os.environ.get("N8N_WEBHOOK_PORT", "8763"))
MAX_ITERATIONS   = 25
TIMEOUT_SHELL    = 120
TIMEOUT_WEB      = 20

# ── ANSI Colors ────────────────────────────────────────────────
C_HEAD   = "\033[38;5;196m"   # red      — agent identity
C_PHASE  = "\033[38;5;208m"   # orange   — phase headers
C_TOOL   = "\033[38;5;226m"   # yellow   — tool calls
C_OBS    = "\033[38;5;82m"    # green    — observations
C_GATE   = "\033[38;5;201m"   # magenta  — approval gate
C_THINK  = "\033[38;5;244m"   # grey     — thinking
C_ACT    = "\033[38;5;39m"    # blue     — LLM output
C_WARN   = "\033[38;5;196m"   # red      — warnings
C_RESET  = "\033[0m"

def cprint(color, text, end="\n"):
    print(f"{color}{text}{C_RESET}", end=end, flush=True)

# ── API keys from Agent-01 .env ────────────────────────────────
def load_env():
    for candidate in [
        Path(__file__).parent / ".env",
        Path(__file__).parent.parent / "agent_01_osint" / ".env",
    ]:
        if candidate.exists():
            for line in candidate.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    os.environ.setdefault(k.strip(), v.strip())
            break

load_env()

# ── Safe vs Offensive tool classification ──────────────────────
SAFE_TOOLS = {"searchsploit", "file_write", "rag_lookup", "advisory_note"}


# ══════════════════════════════════════════════════════════════
#  HUMAN APPROVAL GATE
#  Lives in Python. The LLM cannot reach past this.
# ══════════════════════════════════════════════════════════════
def request_approval(tool: str, command: str, risk: str) -> bool:
    """
    Display a prominent approval prompt and block until the human responds.
    Returns True (execute) or False (skip).
    Calls sys.exit on 'abort'.
    """
    risk_color = {
        "LOW":      "\033[38;5;226m",
        "MEDIUM":   "\033[38;5;208m",
        "HIGH":     "\033[38;5;196m",
        "CRITICAL": "\033[38;5;201m",
    }.get(risk.upper(), "\033[38;5;226m")

    cmd_display = command[:90] + ("..." if len(command) > 90 else "")

    print(f"\n{C_GATE}  ╔{'═'*60}╗")
    print(f"  ║  ⚠   ATTACK ACTION — HUMAN APPROVAL REQUIRED         ║")
    print(f"  ╠{'═'*60}╣")
    print(f"  ║  Tool    : {tool:<49}║")
    print(f"  ║  Command : {cmd_display:<49}║")
    print(f"  ║  Risk    : {risk_color}{risk:<8}{C_GATE}                                       ║")
    print(f"  ╚{'═'*60}╝{C_RESET}")
    print(f"{C_GATE}  Type 'yes' to execute · 'skip' to skip · 'abort' to stop{C_RESET}")

    while True:
        try:
            choice = input(f"{C_GATE}  > {C_RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{C_WARN}[ABORT] Session terminated.{C_RESET}")
            sys.exit(0)

        if choice == "yes":
            cprint(C_OBS, "  [✓] Approved — executing...")
            return True
        elif choice in ("no", "skip", "n"):
            cprint(C_WARN, "  [~] Skipped by operator.")
            return False
        elif choice in ("abort", "exit", "quit"):
            cprint(C_WARN, "\n[ABORT] Red team session terminated by operator.")
            sys.exit(0)
        else:
            print(f"{C_GATE}  Options: 'yes' | 'skip' | 'abort'{C_RESET}")


# ══════════════════════════════════════════════════════════════
#  TOOLS
# ══════════════════════════════════════════════════════════════
def tool_shell(command: str, execute: bool) -> str:
    blocked = ["rm -rf /", "mkfs", ":(){:|:&};:", "dd if=/dev/zero of=/dev/sd",
               "shutdown", "reboot", "halt"]
    for b in blocked:
        if b in command:
            return f"[BLOCKED] Destructive command refused: {b}"

    risk = "HIGH" if any(k in command for k in
                         ["msfconsole", "msfvenom", "exploit", "payload",
                          "reverse_shell", "bind_shell", "nc -e", "bash -i"]) \
           else "MEDIUM" if any(k in command for k in
                                ["nmap", "sqlmap", "nikto", "hydra", "john",
                                 "hashcat", "gobuster", "dirb", "wfuzz"]) \
           else "LOW"

    if not execute:
        return f"[ADVISORY] Would run: {command}"

    if not request_approval("shell", command, risk):
        return f"[SKIPPED] operator declined: {command}"

    cprint(C_TOOL, f"  [SHELL] $ {command}")
    try:
        r = subprocess.run(command, shell=True, capture_output=True,
                           text=True, timeout=TIMEOUT_SHELL)
        out = r.stdout + r.stderr
        if not out.strip():
            return "[SHELL] No output."
        return out[:4000] + (f"\n...[truncated]" if len(out) > 4000 else "")
    except subprocess.TimeoutExpired:
        return f"[SHELL] Timed out after {TIMEOUT_SHELL}s"
    except Exception as e:
        return f"[SHELL] Error: {e}"


def tool_metasploit(resource_commands: str, execute: bool) -> str:
    if not execute:
        return f"[ADVISORY] Would run msfconsole with:\n{resource_commands}"

    if not request_approval("metasploit", resource_commands[:80], "CRITICAL"):
        return "[SKIPPED] operator declined metasploit execution"

    tmp = Path("/tmp/agent05_msf.rc")
    try:
        tmp.write_text(resource_commands)
        cprint(C_TOOL, "  [MSF] Launching msfconsole...")
        r = subprocess.run(["msfconsole", "-q", "-r", str(tmp)],
                           capture_output=True, text=True, timeout=TIMEOUT_SHELL * 3)
        out = r.stdout + r.stderr
        return out[:5000] + ("\n...[truncated]" if len(out) > 5000 else "")
    except FileNotFoundError:
        return "[MSF] msfconsole not found. Is Metasploit installed?"
    except subprocess.TimeoutExpired:
        return f"[MSF] Timed out after {TIMEOUT_SHELL * 3}s"
    except Exception as e:
        return f"[MSF] Error: {e}"
    finally:
        tmp.unlink(missing_ok=True)


def tool_searchsploit(query: str) -> str:
    cprint(C_TOOL, f"  [SEARCHSPLOIT] {query}")
    try:
        r = subprocess.run(["searchsploit", "--json", query],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0 and r.stdout.strip():
            data     = json.loads(r.stdout)
            exploits = data.get("RESULTS_EXPLOIT", [])
            if not exploits:
                return f"[SEARCHSPLOIT] No exploits found for: {query}"
            lines = [f"[SEARCHSPLOIT] {len(exploits)} exploits for '{query}':"]
            for e in exploits[:12]:
                lines.append(f"  EDB-{e.get('EDB-ID','?')} | {e.get('Title','?')} "
                              f"| {e.get('Type','?')} | {e.get('Platform','?')}")
            return "\n".join(lines)
    except FileNotFoundError:
        pass
    except Exception:
        pass
    try:
        import requests as _req
        r = _req.get("https://www.exploit-db.com/search",
                     params={"q": query}, timeout=TIMEOUT_WEB,
                     headers={"User-Agent": "Mozilla/5.0",
                              "Accept": "application/json",
                              "X-Requested-With": "XMLHttpRequest"})
        items = r.json().get("data", [])[:10]
        if not items:
            return f"[SEARCHSPLOIT] No exploits found online for: {query}"
        lines = [f"[SEARCHSPLOIT] {len(items)} results (web):"]
        for item in items:
            lines.append(f"  EDB-{item.get('id','?')} | {item.get('description','?')[:80]}")
        return "\n".join(lines)
    except Exception as e:
        return f"[SEARCHSPLOIT] Error: {e}"


def tool_rag_lookup(query: str) -> str:
    cprint(C_TOOL, f"  [RAG] {query}")
    try:
        import chromadb
        from chromadb.config import Settings as CS
        client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT,
                                     settings=CS(anonymized_telemetry=False))
        client.heartbeat()
        col   = client.get_collection("security_docs")
        count = col.count()
        if count == 0:
            return "[RAG] Knowledge base empty."
        res    = col.query(query_texts=[query], n_results=min(3, count),
                           include=["documents", "metadatas", "distances"])
        chunks = []
        for doc, meta, dist in zip(res["documents"][0],
                                   res["metadatas"][0],
                                   res["distances"][0]):
            rel = round((1 - dist) * 100, 1)
            chunks.append(f"[{meta.get('source','?')} | {rel}%]\n{doc[:500]}")
        return "\n---\n".join(chunks) if chunks else "[RAG] No relevant results."
    except Exception as e:
        return f"[RAG] Unavailable: {e}"


def tool_file_write(filename: str, content: str) -> str:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r'[^\w\-_\.]', '_', filename)
    if not safe.endswith(('.md', '.txt')):
        safe += '.md'
    path = REPORTS_DIR / safe
    path.write_text(content, encoding='utf-8')
    cprint(C_TOOL, f"  [FILE] Saved: {path}")
    return f"[FILE_WRITE] Saved: {path}"


TOOLS = {
    "shell":        tool_shell,
    "metasploit":   tool_metasploit,
    "searchsploit": tool_searchsploit,
    "rag_lookup":   tool_rag_lookup,
    "file_write":   tool_file_write,
}


def dispatch_tool(name: str, inp: str, execute: bool) -> str:
    name = name.strip().lower()
    if name not in TOOLS:
        return f"[ERROR] Unknown tool '{name}'. Available: {list(TOOLS.keys())}"
    if name in ("shell", "metasploit"):
        return TOOLS[name](inp.strip(), execute)
    if name == "file_write":
        parts = inp.strip().split('\n', 1)
        return TOOLS[name](parts[0].strip(), parts[1].strip() if len(parts) == 2 else inp)
    return TOOLS[name](inp.strip())


# ══════════════════════════════════════════════════════════════
#  LLM
# ══════════════════════════════════════════════════════════════
def call_llm(messages: list, num_predict: int = 2048) -> str:
    import requests
    url     = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/chat"
    payload = {
        "model":    AGENT_MODEL,
        "messages": messages,
        "stream":   True,
        "options": {
            "temperature": 0.1,
            "num_predict": num_predict,
            "num_ctx":     8192,
            "top_p":       0.9,
            "stop":        ["\nOBSERVATION:", "[Wait", "[After"],
        }
    }
    try:
        r = requests.post(url, json=payload, stream=True, timeout=300)
        r.raise_for_status()
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Cannot reach ollama at {OLLAMA_HOST}:{OLLAMA_PORT}")
        sys.exit(1)

    full        = ""
    in_think    = False
    think_shown = False

    for line in r.iter_lines():
        if not line:
            continue
        data        = json.loads(line)
        msg         = data.get("message", {})
        token       = msg.get("content", "")
        think_token = msg.get("thinking", "")

        if think_token:
            if not think_shown:
                print(f"\n{C_THINK}  ┌─ THINKING {'─'*47}{C_RESET}")
                think_shown = True
                in_think    = True
            print(f"{C_THINK}{think_token}{C_RESET}", end="", flush=True)

        if token and in_think:
            print(f"\n{C_THINK}  └─ {'─'*53}{C_RESET}\n")
            in_think = False

        if token:
            if not think_shown:
                print(f"\n{C_THINK}  ┌─ THINKING {'─'*47}{C_RESET}")
                print(f"{C_THINK}  [no thinking tokens]{C_RESET}")
                print(f"{C_THINK}  └─ {'─'*53}{C_RESET}\n")
                think_shown = True
            print(f"{C_ACT}{token}{C_RESET}", end="", flush=True)
            full += token

        if data.get("done"):
            if in_think:
                print(f"\n{C_THINK}  └─ {'─'*53}{C_RESET}\n")
            break

    print()
    return full


def parse_response(response: str) -> dict:
    result = {"thought": "", "action": None, "input": None,
              "risk": "MEDIUM", "final_answer": None}
    clean  = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL).strip()

    fa = re.search(r'FINAL_ANSWER:\s*(.*?)$', clean, re.DOTALL | re.IGNORECASE)
    if fa:
        t = re.search(r'THOUGHT:\s*(.*?)(?=FINAL_ANSWER:)', clean,
                      re.DOTALL | re.IGNORECASE)
        result["thought"]      = t.group(1).strip() if t else ""
        result["final_answer"] = fa.group(1).strip()
        return result

    if re.search(r'ACTION:\s*FINAL_ANSWER', clean, re.IGNORECASE):
        inp = re.search(r'INPUT:\s*(.*?)$', clean, re.DOTALL | re.IGNORECASE)
        t   = re.search(r'THOUGHT:\s*(.*?)(?=ACTION:)', clean, re.DOTALL | re.IGNORECASE)
        result["thought"]      = t.group(1).strip() if t else ""
        result["final_answer"] = inp.group(1).strip() if inp else result["thought"]
        return result

    t = re.search(r'THOUGHT:\s*(.*?)(?=ACTION:|FINAL_ANSWER:)', clean,
                  re.DOTALL | re.IGNORECASE)
    a = re.search(r'ACTION:\s*(\w+)', clean, re.IGNORECASE)
    i = re.search(r'INPUT:\s*(.*?)(?=\nRISK:|\nTHOUGHT:|\nACTION:|\nFINAL_ANSWER:|$)',
                  clean, re.DOTALL | re.IGNORECASE)
    risk_m = re.search(r'RISK:\s*(\w+)', clean, re.IGNORECASE)

    if t:
        result["thought"] = t.group(1).strip()
    if a:
        result["action"] = a.group(1).strip()
    if i:
        result["input"] = i.group(1).strip()
    if risk_m:
        result["risk"] = risk_m.group(1).upper()
    return result


# ══════════════════════════════════════════════════════════════
#  PHASE 1 — ADVISORY ANALYSIS
# ══════════════════════════════════════════════════════════════
ADVISORY_SYSTEM = """You are Agent-05, an expert red team operator and penetration tester with 15 years of experience.

Your task is to produce a comprehensive adversarial analysis of the provided target intelligence.

Structure your response EXACTLY as follows:

## 1. Attack Surface Summary
List every exposed service, port, and entry point with a one-line risk note.

## 2. Vulnerability Assessment
For each CVE or known weakness:
- CVE ID + CVSS score
- Exploitability (remote/local, auth required, complexity)
- Impact if exploited

## 3. Attack Chain (Kill Chain)
Step-by-step attack path from initial access to objective. Use numbered steps.
Map each step to a MITRE ATT&CK technique ID (e.g. T1190, T1059.001).

## 4. Tool Recommendations
For each attack step, the exact tool and command skeleton:
  searchsploit, metasploit module path, sqlmap flags, etc.

## 5. Risk Priority Matrix
| Service | CVE | Severity | Ease | Priority |
|---------|-----|----------|------|----------|
(fill table)

## 6. Recommendations for Defender
Brief blue team mitigations for each identified risk.

Be precise, technical, and actionable. Include real CVE IDs, real Metasploit module paths, real tool flags."""


def run_advisory(target: str, context: str) -> str:
    cprint(C_PHASE, f"\n{'═'*62}")
    cprint(C_PHASE,  "  PHASE 1 — ADVISORY ANALYSIS")
    cprint(C_PHASE, f"{'═'*62}\n")

    messages = [
        {"role": "system", "content": ADVISORY_SYSTEM},
        {"role": "user",   "content": (
            f"TARGET: {target}\n\n"
            f"INTELLIGENCE FROM RECON:\n{context}\n\n"
            f"Produce the full adversarial analysis now."
        )}
    ]
    return call_llm(messages, num_predict=3000)


# ══════════════════════════════════════════════════════════════
#  PHASE 2 — ACTIVE REACT LOOP
# ══════════════════════════════════════════════════════════════
ACTIVE_SYSTEM = """You are Agent-05, an autonomous red team agent operating in controlled, authorized penetration testing.

AVAILABLE TOOLS:
  shell         — run any shell command (nmap, hydra, netcat, custom scripts)
  metasploit    — run msfconsole with resource commands
  searchsploit  — search local exploit-db (read-only, no approval needed)
  rag_lookup    — query local knowledge base (read-only, no approval needed)
  file_write    — save report to disk (no approval needed)

FORMAT FOR EVERY RESPONSE — ONE STEP AT A TIME:
THOUGHT: <one sentence reasoning>
ACTION: <tool_name>
INPUT: <exact command or input>
RISK: <LOW|MEDIUM|HIGH|CRITICAL>

WHEN DONE:
THOUGHT: <summary>
FINAL_ANSWER: <complete findings>

STRICT RULES:
1. ONE action per response — never chain commands
2. Every offensive action (shell/metasploit) requires human approval — you will be informed if it was approved or skipped
3. RISK field is mandatory for shell/metasploit actions
4. If an action is skipped by the operator, note it and move to the next logical step
5. Stop at FINAL_ANSWER when the objective is complete or max steps reached
6. NEVER attempt to bypass the approval system"""

FORMAT_REMINDER = (
    "\n\nFORMAT REMINDER:\n"
    "  Tool call: THOUGHT: ... | ACTION: <tool> | INPUT: ... | RISK: LOW|MEDIUM|HIGH|CRITICAL\n"
    "  Done:      THOUGHT: ... | FINAL_ANSWER: ..."
)


def run_active(target: str, context: str, advisory: str, execute: bool) -> str:
    cprint(C_PHASE, f"\n{'═'*62}")
    cprint(C_PHASE,  "  PHASE 2 — ACTIVE EXPLOITATION")
    if not execute:
        cprint(C_WARN, "  [!] --execute not set — showing commands only (advisory preview)")
    cprint(C_PHASE, f"{'═'*62}\n")

    messages = [
        {"role": "system", "content": ACTIVE_SYSTEM},
        {"role": "user",   "content": (
            f"TARGET: {target}\n\n"
            f"RECON CONTEXT:\n{context[:2000]}\n\n"
            f"ADVISORY ANALYSIS SUMMARY:\n{advisory[:2000]}\n\n"
            f"Execute the attack plan now. Begin with the highest-priority vector.\n"
            f"One step at a time.{FORMAT_REMINDER}"
        )}
    ]

    final_answer   = None
    iteration      = 0
    action_history = []

    while iteration < MAX_ITERATIONS:
        iteration += 1
        cprint(C_HEAD, f"\n{'-'*62}")
        cprint(C_HEAD, f"  Step {iteration}/{MAX_ITERATIONS}")
        cprint(C_HEAD, f"{'-'*62}")

        response = call_llm(messages)
        parsed   = parse_response(response)
        messages.append({"role": "assistant", "content": response})

        if parsed["final_answer"]:
            final_answer = parsed["final_answer"]
            cprint(C_HEAD, f"\n{'═'*62}")
            cprint(C_HEAD, f"  ACTIVE PHASE COMPLETE — {iteration} steps")
            cprint(C_HEAD, f"{'═'*62}")
            break

        if parsed["action"] and parsed["input"]:
            key          = f"{parsed['action']}::{parsed['input'][:100]}"
            repeat_count = action_history.count(key)

            if repeat_count >= 2:
                cprint(C_WARN, f"\n  [LOOP] Same action x{repeat_count+1} — forcing next step")
                messages.append({
                    "role":    "user",
                    "content": (
                        f"You repeated this action {repeat_count+1} times. STOP.\n"
                        f"Move to the next step in the attack chain.{FORMAT_REMINDER}"
                    )
                })
                continue

            action_history.append(key)
            cprint(C_TOOL, f"\n  -> {parsed['action']} [RISK: {parsed.get('risk','?')}]")

            observation = dispatch_tool(parsed["action"], parsed["input"], execute)
            preview     = observation[:600] + ("..." if len(observation) > 600 else "")
            cprint(C_OBS, f"\n  [OBSERVATION]\n{preview}")

            approved = "[SKIPPED]" not in observation and "[ADVISORY]" not in observation
            messages.append({
                "role":    "user",
                "content": (
                    f"OBSERVATION from {parsed['action']} "
                    f"({'EXECUTED' if approved else 'SKIPPED/ADVISORY'}):\n"
                    f"{observation}"
                    f"{FORMAT_REMINDER}"
                )
            })

        else:
            cprint(C_WARN, "  [PARSER] No action — nudging model")
            messages.append({
                "role":    "user",
                "content": (
                    f"Output your next action NOW:\n"
                    f"THOUGHT: <one sentence>\n"
                    f"ACTION: <tool>\n"
                    f"INPUT: <command>\n"
                    f"RISK: <level>\n"
                    f"Or write FINAL_ANSWER: if done.{FORMAT_REMINDER}"
                )
            })

    if not final_answer:
        final_answer = f"Max iterations ({MAX_ITERATIONS}) reached. Check reports/ for saved output."
        cprint(C_WARN, "\n[!] Max iterations reached.")

    return final_answer


# ══════════════════════════════════════════════════════════════
#  REPORT INGESTOR  (parse Agent-04 master report)
# ══════════════════════════════════════════════════════════════
def ingest_report(report_path: str) -> tuple[str, str]:
    """Parse an Agent-04 MASTER report. Returns (target, context_text)."""
    path = Path(report_path)
    if not path.exists():
        # glob support — e.g. reports/MASTER_*.md
        matches = sorted(REPORTS_DIR.glob(Path(report_path).name))
        if not matches:
            print(f"[ERROR] Report not found: {report_path}")
            sys.exit(1)
        path = matches[-1]   # latest

    text = path.read_text(encoding="utf-8", errors="replace")

    # Extract target from markdown table
    target_m = re.search(r'\|\s*Target\s*\|\s*`([^`]+)`', text)
    target   = target_m.group(1) if target_m else path.stem

    cprint(C_HEAD, f"  [REPORT] Loaded: {path.name}")
    cprint(C_HEAD, f"  [REPORT] Target extracted: {target}")

    # Trim to context limit
    context = text[:6000]
    return target, context


# ══════════════════════════════════════════════════════════════
#  MASTER REPORT WRITER
# ══════════════════════════════════════════════════════════════
def write_redteam_report(target: str, mode: str, advisory: str,
                          active_result: str, ts: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r'[^\w\-_]', '_', target)[:40]
    path = REPORTS_DIR / f"REDTEAM_{safe}_{ts}.md"

    lines = [
        "# AGENTS-HQ — Red Team Report",
        "",
        f"| Field       | Value |",
        f"|-------------|-------|",
        f"| Target      | `{target}` |",
        f"| Mode        | {mode} |",
        f"| Agent       | Agent-05 Red Team v1 |",
        f"| Generated   | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |",
        "",
        "---",
        "",
        "## Phase 1 — Advisory Analysis",
        "",
        advisory,
        "",
    ]

    if active_result:
        lines += [
            "---",
            "",
            "## Phase 2 — Active Execution Results",
            "",
            active_result,
            "",
        ]

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# ══════════════════════════════════════════════════════════════
#  ORCHESTRATOR
# ══════════════════════════════════════════════════════════════
def run_engagement(target: str, context: str, mode: str, execute: bool) -> str:
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    cprint(C_HEAD, f"\n{'═'*62}")
    cprint(C_HEAD,  "  AGENT-05 — RED TEAM")
    cprint(C_HEAD, f"  Target  : {target}")
    cprint(C_HEAD, f"  Mode    : {mode}  |  Execute: {execute}")
    cprint(C_HEAD, f"{'═'*62}")

    # Phase 1 — always
    advisory = run_advisory(target, context)

    # Phase 2 — only in active mode
    active_result = ""
    if mode == "active":
        if not execute:
            cprint(C_WARN, "\n  [!] Active mode requires --execute flag.")
            cprint(C_WARN,  "      Showing advisory preview of attack steps only.\n")
        active_result = run_active(target, context, advisory, execute)

    # Write report
    report = write_redteam_report(target, mode, advisory, active_result, ts)

    cprint(C_HEAD, f"\n{'═'*62}")
    cprint(C_HEAD,  "  ENGAGEMENT COMPLETE")
    cprint(C_OBS,  f"  Report: reports/{report.name}")
    cprint(C_HEAD, f"{'═'*62}\n")

    return report.read_text()


# ══════════════════════════════════════════════════════════════
#  n8n WEBHOOK SERVER  (advisory only — active requires CLI)
# ══════════════════════════════════════════════════════════════
def run_webhook_server():
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                try:
                    self.wfile.write(b'{"status":"ok","agent":"05"}')
                except BrokenPipeError:
                    pass
            else:
                self.send_response(404)
                self.end_headers()
        def do_POST(self):
            if self.path == "/webhook/agent05":
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                try:
                    data    = json.loads(body)
                    target  = data.get("target", "").strip()
                    context = data.get("context", "No additional context provided.")
                    if not target:
                        raise ValueError("'target' field required")
                    cprint(C_HEAD, f"\n[WEBHOOK] Advisory for: {target}")
                    # Webhooks are advisory-only — active mode requires human at terminal
                    advisory = run_advisory(target, context)
                    ts       = datetime.now().strftime('%Y%m%d_%H%M%S')
                    report   = write_redteam_report(target, "advisory", advisory, "", ts)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "status":  "complete",
                        "target":  target,
                        "mode":    "advisory",
                        "report":  str(report),
                        "result":  advisory,
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
            cprint(C_TOOL, f"  [HTTP] {fmt % args}")

    cprint(C_HEAD, f"\n{'═'*62}")
    cprint(C_HEAD,  "  AGENT-05 RED TEAM — Webhook Server")
    cprint(C_HEAD, f"  Listening : 127.0.0.1:{N8N_WEBHOOK_PORT}")
    cprint(C_HEAD,  "  Endpoint  : POST /webhook/agent05")
    cprint(C_HEAD,  '  Body      : {"target":"192.168.1.10","context":"..."}')
    cprint(C_HEAD,  "  Note      : webhook = advisory only (active needs CLI)")
    cprint(C_HEAD, f"{'═'*62}\n")
    HTTPServer(("127.0.0.1", N8N_WEBHOOK_PORT), Handler).serve_forever()


# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="Agent-05 Red Team — adversarial intelligence and exploitation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Modes:
  advisory  Phase 1 only — full attack analysis, no execution (default)
  active    Phase 1 + Phase 2 — requires --execute for real execution

The --execute flag is a second, explicit confirmation that you authorize
active exploitation. Without it, active mode shows commands but won't run them.

Examples:
  python3 agent_05_redteam.py --target 192.168.1.10
  python3 agent_05_redteam.py --target 192.168.1.10 --mode active --execute
  python3 agent_05_redteam.py --report reports/MASTER_192_168_1_10_*.md --mode active --execute
  python3 agent_05_redteam.py --task "web app on http://192.168.1.10:8080"
  python3 agent_05_redteam.py --n8n-server
        """,
    )
    parser.add_argument("--target",  "-t", help="Target IP / domain / CIDR")
    parser.add_argument("--report",  "-r", help="Path to Agent-04 MASTER report to use as input")
    parser.add_argument("--task",    "-k", help="Free-text engagement description")
    parser.add_argument("--context", "-c", default="", help="Additional context string")
    parser.add_argument("--mode",    "-m", default="advisory",
                        choices=["advisory", "active"])
    parser.add_argument("--execute",       action="store_true",
                        help="Authorize active execution (required for --mode active to run)")
    parser.add_argument("--interactive",   action="store_true")
    parser.add_argument("--n8n-server",    action="store_true")
    args = parser.parse_args()

    if args.n8n_server:
        run_webhook_server()
        return

    # Interactive mode
    if args.interactive:
        cprint(C_HEAD, "\nAGENT-05 RED TEAM — Interactive Mode")
        print("Target (IP / domain) or path to MASTER report: ", end="")
        raw = input().strip()
        if not raw:
            sys.exit(0)
        print("Mode [advisory / active] (default: advisory): ", end="")
        m = input().strip().lower()
        args.mode = m if m in ("advisory", "active") else "advisory"

        if args.mode == "active":
            cprint(C_GATE, "\nActive mode selected.")
            cprint(C_GATE, "Type 'yes' to authorize execution, anything else for advisory preview: ")
            confirm = input("  > ").strip()
            args.execute = (confirm == "yes")

        if Path(raw).exists() or raw.startswith("reports/"):
            args.report = raw
        else:
            args.target = raw

    # Resolve target + context
    if args.report:
        target, context = ingest_report(args.report)
        if args.context:
            context += f"\n\nAdditional context: {args.context}"
    elif args.target or args.task:
        target  = args.target or args.task
        context = args.context or "No prior recon data. Run your own initial enumeration."
    else:
        parser.print_help()
        sys.exit(0)

    # Safety banner for active mode
    if args.mode == "active" and args.execute:
        cprint(C_GATE, f"\n{'╔' + '═'*60 + '╗'}")
        cprint(C_GATE,  "  ║  ⚠  ACTIVE EXPLOITATION MODE ENABLED                  ║")
        cprint(C_GATE,  "  ║  Every attack action will prompt for your approval.    ║")
        cprint(C_GATE,  "  ║  Type 'abort' at any prompt to stop immediately.       ║")
        cprint(C_GATE, f"  {'╚' + '═'*60 + '╝'}")
        print()

    result = run_engagement(target, context, args.mode, args.execute)
    print(result[:3000])


if __name__ == "__main__":
    main()
