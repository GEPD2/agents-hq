#!/usr/bin/env python3
"""
AGENTS-HQ - Agent-02 Task Agent v4
ReAct loop with live thinking display + robust parser

Model:  deepseek-r1:8b
Tools:  shell | web_search (NVD) | exploitdb | rag_lookup | file_write | python_exec

Fixes in v4:
  - think:True passed to ollama = thinking tokens budgeted separately from content
  - num_predict 512 for content only — thinking never starves content tokens
  - FINAL_ANSWER caught in ALL formats (keyword, ACTION: FINAL_ANSWER, INPUT:)
  - FORMAT_REMINDER appended to every user message
  - Empty response handler: concise nudge, not long explanation
  - MAX_ITERATIONS 20
  - Workflow simplified: one exploitdb + one web_search total

Usage:
    python3 agent.py --target 192.168.1.1 --sudo-pass-file .credentials
    python3 agent.py "custom task"
    python3 agent.py --interactive
"""

import sys
import json
import subprocess
import argparse
import requests
import re
import stat
from datetime import datetime
from pathlib import Path

# ── Config ────────────────────────────────────────────────────
OLLAMA_HOST    = "localhost"
OLLAMA_PORT    = 11434
AGENT_MODEL    = "deepseek-r1:8b"
MAX_ITERATIONS = 20
REPORTS_DIR    = Path(__file__).parent.parent / "reports"
TIMEOUT_SHELL  = 120
TIMEOUT_WEB    = 15
SUDO_PASS      = ""

# ── ANSI Colors ───────────────────────────────────────────────
C_THINK = "\033[38;5;244m"
C_HEAD  = "\033[38;5;39m"
C_TOOL  = "\033[38;5;208m"
C_OBS   = "\033[38;5;82m"
C_WARN  = "\033[38;5;196m"
C_ACT   = "\033[38;5;226m"
C_RESET = "\033[0m"

def cprint(color, text, end="\n"):
    print(f"{color}{text}{C_RESET}", end=end, flush=True)

# ── System Prompt ─────────────────────────────────────────────
SYSTEM_PROMPT = """You are Agent-02, an autonomous cybersecurity recon agent.
You operate in a strict one-step-at-a-time ReAct loop.

AVAILABLE TOOLS (the ONLY valid ACTION values):
  shell, web_search, exploitdb, rag_lookup, file_write, python_exec

FORMAT FOR TOOL CALLS:
THOUGHT: <one sentence>
ACTION: <tool_name>
INPUT: <input>

FORMAT WHEN TASK IS COMPLETE:
THOUGHT: <summary>
FINAL_ANSWER: <complete findings>

CRITICAL: FINAL_ANSWER is a KEYWORD not a tool.
NEVER write "ACTION: FINAL_ANSWER" — that causes an error and wastes a step.
Write "FINAL_ANSWER:" directly after THOUGHT: when done.

STRICT RULES:
1. ONE THOUGHT + ONE ACTION + ONE INPUT per response
2. OR THOUGHT + FINAL_ANSWER when all steps complete
3. NEVER plan multiple steps ahead
4. NEVER write [Wait for results] or [After receiving]
5. STOP after the INPUT line or FINAL_ANSWER line
6. KEEP THINKING SHORT — max 3-4 sentences, then write the action immediately
7. Do NOT deliberate endlessly — decide quickly and commit

RECON WORKFLOW:
Step 1 — shell      : nmap -sS -sV -sC --open <target>
Step 2 — rag_lookup : one query covering all found services
Step 3 — exploitdb  : search most critical service+version only
Step 4 — web_search : NVD CVEs for most critical service only
Step 5 — file_write : save full markdown report
Step 6 — THOUGHT then FINAL_ANSWER: (NOT ACTION: FINAL_ANSWER)

RULES:
- If ChromaDB unavailable on rag_lookup skip immediately to exploitdb
- If tool returns no data move to next step never retry same query
- Use specific service name and version in exploitdb/web_search queries"""

FORMAT_REMINDER = (
    "\n\nFORMAT REMINDER:\n"
    "  Tool: THOUGHT: ... / ACTION: <toolname> / INPUT: ...\n"
    "  Done: THOUGHT: ... / FINAL_ANSWER: ... (NOT 'ACTION: FINAL_ANSWER')\n"
    "  IMPORTANT: Think max 3 sentences then write THOUGHT/ACTION/INPUT immediately."
)


# ── Tools ─────────────────────────────────────────────────────

def tool_shell(command):
    blocked = ["rm -rf /", "mkfs", ":(){:|:&};:", "dd if=/dev/zero of=/dev/sd"]
    for b in blocked:
        if b in command:
            return f"[BLOCKED] Dangerous command: {b}"
    priv_flags = ["-sS", "-sU", "-sA", "-sW", "-sM", "-O", "--osscan"]
    needs_sudo = any(f in command for f in priv_flags)
    if "nmap" in command and needs_sudo and "sudo" not in command:
        if SUDO_PASS:
            command = "echo '" + SUDO_PASS + "' | sudo -S " + command
        else:
            command = "sudo " + command
    display = command.replace(SUDO_PASS, "***") if SUDO_PASS else command
    cprint(C_TOOL, f"  [SHELL] $ {display}")
    try:
        result = subprocess.run(command, shell=True, capture_output=True,
                                text=True, timeout=TIMEOUT_SHELL)
        output = result.stdout + result.stderr
        if SUDO_PASS:
            output = output.replace(SUDO_PASS, "***")
        if not output.strip():
            return "[SHELL] No output."
        if len(output) > 4000:
            output = output[:4000] + f"\n...[truncated {len(output)} chars]"
        return output
    except subprocess.TimeoutExpired:
        return f"[SHELL] Timed out after {TIMEOUT_SHELL}s"
    except Exception as e:
        return f"[SHELL] Error: {e}"


def tool_web_search(query):
    cprint(C_TOOL, f"  [WEB] Searching: {query}")
    cve_match = re.search(r'CVE-\d{4}-\d+', query, re.IGNORECASE)
    if cve_match:
        try:
            cve = cve_match.group(0).upper()
            r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                             params={"cveId": cve}, timeout=TIMEOUT_WEB,
                             headers={"User-Agent": "AGENTS-HQ/1.0"})
            vulns = r.json().get("vulnerabilities", [])
            if vulns:
                c = vulns[0]["cve"]
                desc = next((d["value"] for d in c.get("descriptions", [])
                             if d["lang"] == "en"), "No description")
                metrics = c.get("metrics", {})
                score = ""
                if metrics.get("cvssMetricV31"):
                    s = metrics["cvssMetricV31"][0]["cvssData"]
                    score = (f"CVSS v3.1: {s['baseScore']} ({s['baseSeverity']})"
                             f" | {s['vectorString']}")
                elif metrics.get("cvssMetricV2"):
                    s = metrics["cvssMetricV2"][0]["cvssData"]
                    score = f"CVSS v2: {s['baseScore']} | {s['vectorString']}"
                refs = "\n".join(f"  {x['url']}" for x in c.get("references", [])[:3])
                return f"[NVD] {cve}\nDescription: {desc}\n{score}\nRefs:\n{refs}"
        except Exception:
            pass
    cve_kw = ["cve", "vulnerability", "vuln", "exploit", "rce", "sqli"]
    if any(k in query.lower() for k in cve_kw):
        clean = re.sub(r'cve\s*', '', query, flags=re.IGNORECASE).strip()
        try:
            r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                             params={"keywordSearch": clean, "resultsPerPage": 5},
                             timeout=TIMEOUT_WEB, headers={"User-Agent": "AGENTS-HQ/1.0"})
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                out = [f"[NVD] {data.get('totalResults', 0)} CVEs for: {clean}"]
                for v in vulns[:5]:
                    c = v["cve"]
                    desc = next((d["value"] for d in c.get("descriptions", [])
                                 if d["lang"] == "en"), "")[:200]
                    m = c.get("metrics", {})
                    score = ""
                    if m.get("cvssMetricV31"):
                        score = f"[CVSS {m['cvssMetricV31'][0]['cvssData']['baseScore']}]"
                    elif m.get("cvssMetricV2"):
                        score = f"[CVSS {m['cvssMetricV2'][0]['cvssData']['baseScore']}]"
                    out.append(f"  {c['id']} {score}: {desc}")
                return "\n".join(out)
        except Exception:
            pass
    try:
        r = requests.get("https://html.duckduckgo.com/html/?q=" + requests.utils.quote(query),
                         timeout=TIMEOUT_WEB, headers={"User-Agent": "Mozilla/5.0"})
        snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', r.text, re.DOTALL)
        snippets = [re.sub(r'<[^>]+>', '', s).strip() for s in snippets[:5]]
        return "\n".join(snippets) if snippets else "No results found."
    except Exception as e:
        return f"[WEB_SEARCH] Error: {e}"


def tool_exploitdb(query):
    cprint(C_TOOL, f"  [EXPLOITDB] Searching: {query}")
    try:
        result = subprocess.run(["searchsploit", "--json", query],
                                capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                exploits = data.get("RESULTS_EXPLOIT", [])
                if not exploits:
                    return f"[EXPLOITDB] No exploits found for: {query}"
                out = [f"[EXPLOITDB] {len(exploits)} exploits for '{query}':"]
                for e in exploits[:10]:
                    out.append(f"  EDB-{e.get('EDB-ID','?')} | {e.get('Title','?')} "
                               f"| {e.get('Type','?')} | {e.get('Platform','?')}")
                return "\n".join(out)
            except json.JSONDecodeError:
                pass
        result2 = subprocess.run(["searchsploit", query],
                                 capture_output=True, text=True, timeout=30)
        if result2.returncode == 0 and "Exploit Title" in result2.stdout:
            return f"[EXPLOITDB]\n{result2.stdout[:3000]}"
    except FileNotFoundError:
        pass
    except Exception as e:
        return f"[EXPLOITDB] Error: {e}"
    try:
        r = requests.get("https://www.exploit-db.com/search", params={"q": query},
                         timeout=TIMEOUT_WEB,
                         headers={"User-Agent": "Mozilla/5.0",
                                  "Accept": "application/json",
                                  "X-Requested-With": "XMLHttpRequest"})
        items = r.json().get("data", [])[:8]
        if not items:
            return f"[EXPLOITDB] No exploits found for: {query}"
        out = [f"[EXPLOITDB] {len(items)} results:"]
        for item in items:
            out.append(f"  EDB-{item.get('id','?')} | {item.get('description','?')}")
        return "\n".join(out)
    except Exception as e:
        return f"[EXPLOITDB] Web API error: {e}"


def tool_rag_lookup(query):
    cprint(C_TOOL, f"  [RAG] Querying knowledge base: {query}")
    try:
        import chromadb
        from chromadb.config import Settings as CS
        client = chromadb.HttpClient(host="localhost", port=8000,
                                     settings=CS(anonymized_telemetry=False))
        client.heartbeat()
        try:
            col = client.get_collection("security_docs")
        except Exception:
            return "[RAG] Collection 'security_docs' not found. Run agent_03_rag/ingest.py first."
        count = col.count()
        if count == 0:
            return "[RAG] Knowledge base empty. Ingest documents first."
        results = col.query(query_texts=[query], n_results=min(3, count),
                            include=["documents", "metadatas", "distances"])
        chunks = []
        for doc, meta, dist in zip(results["documents"][0],
                                   results["metadatas"][0],
                                   results["distances"][0]):
            rel = round((1 - dist) * 100, 1)
            chunks.append(
                f"[Source: {meta.get('source','?')} | Relevance: {rel}%]\n{doc[:600]}"
            )
        if not chunks:
            return f"[RAG] No relevant documents for: {query}"
        return f"[RAG] Results for '{query}':\n\n" + "\n---\n".join(chunks)
    except Exception as e:
        return f"[RAG] ChromaDB unavailable: {e}"


def tool_file_write(filename, content):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r'[^\w\-_\.]', '_', filename)
    if not safe.endswith(('.md', '.txt', '.html')):
        safe += '.md'
    filepath = REPORTS_DIR / safe
    try:
        filepath.write_text(content, encoding='utf-8')
        cprint(C_TOOL, f"  [FILE] Saved: {filepath}")
        return f"[FILE_WRITE] Saved: {filepath}"
    except Exception as e:
        return f"[FILE_WRITE] Error: {e}"


def tool_python_exec(code):
    cprint(C_TOOL, "  [PYTHON] Executing...")
    tmp = Path("/tmp/agent02_exec.py")
    try:
        tmp.write_text(code)
        r = subprocess.run([sys.executable, str(tmp)],
                           capture_output=True, text=True, timeout=30)
        out = r.stdout + r.stderr
        if len(out) > 3000:
            out = out[:3000] + "\n...[truncated]"
        return out if out.strip() else "[PYTHON] No output."
    except subprocess.TimeoutExpired:
        return "[PYTHON] Timed out after 30s"
    except Exception as e:
        return f"[PYTHON] Error: {e}"
    finally:
        tmp.unlink(missing_ok=True)


TOOLS = {
    "shell":       tool_shell,
    "web_search":  tool_web_search,
    "exploitdb":   tool_exploitdb,
    "rag_lookup":  tool_rag_lookup,
    "file_write":  tool_file_write,
    "python_exec": tool_python_exec,
}


def dispatch_tool(name, inp):
    name = name.strip().lower()
    if name not in TOOLS:
        return f"[ERROR] Unknown tool '{name}'. Available: {list(TOOLS.keys())}"
    if name == "file_write":
        parts = inp.strip().split('\n', 1)
        if len(parts) == 2:
            return TOOLS[name](parts[0].strip(), parts[1].strip())
        return TOOLS[name]("report.md", inp)
    return TOOLS[name](inp.strip())


# ── LLM ───────────────────────────────────────────────────────
def call_llm(messages):
    url = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/chat"
    payload = {
        "model":    AGENT_MODEL,
        "messages": messages,
        "stream":   True,
        "think":    False,          # disable separate thinking — use stop tokens instead
        "options": {
            "temperature": 0.1,
            "num_predict": 1024,    # total token budget (thinking + content)
            "num_ctx":     8192,
            "top_p":       0.9,
            "stop": ["\nOBSERVATION:", "[Wait", "[After",
                     "\nTHOUGHT:\nACTION:"]   # prevent second block
        }
    }
    try:
        r = requests.post(url, json=payload, stream=True, timeout=180)
        r.raise_for_status()
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Cannot reach ollama at {OLLAMA_HOST}:{OLLAMA_PORT}")
        sys.exit(1)

    full          = ""
    thinking_text = ""
    in_think      = False
    think_opened  = False

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
                think_opened = True
                in_think     = True
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

    clean = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL).strip()
    clean = re.sub(r'\[Wait[^\]]*\]', '', clean)
    clean = re.sub(r'\[After[^\]]*\]', '', clean).strip()

    if not clean:
        cprint(C_WARN, "  [PARSER] Empty content — thinking used all tokens")
        return result

    # Correct format: FINAL_ANSWER: text
    fa = re.search(r'FINAL_ANSWER:\s*(.*?)$', clean, re.DOTALL | re.IGNORECASE)
    if fa:
        t = re.search(r'THOUGHT:\s*(.*?)(?=FINAL_ANSWER:)', clean, re.DOTALL | re.IGNORECASE)
        result["thought"]      = t.group(1).strip() if t else ""
        result["final_answer"] = fa.group(1).strip()
        return result

    # Wrong but recoverable: ACTION: FINAL_ANSWER
    if re.search(r'ACTION:\s*FINAL_ANSWER', clean, re.IGNORECASE):
        inp = re.search(r'INPUT:\s*(.*?)$', clean, re.DOTALL | re.IGNORECASE)
        t   = re.search(r'THOUGHT:\s*(.*?)(?=ACTION:)', clean, re.DOTALL | re.IGNORECASE)
        result["thought"]      = t.group(1).strip() if t else ""
        result["final_answer"] = inp.group(1).strip() if inp else result["thought"]
        cprint(C_WARN, "  [PARSER] Caught 'ACTION: FINAL_ANSWER' — recovered")
        return result

    # Multi-step: keep only first block
    positions = [m.start() for m in re.finditer(r'^ACTION:', clean,
                                                  re.MULTILINE | re.IGNORECASE)]
    if len(positions) > 1:
        fb = re.search(
            r'(THOUGHT:.*?ACTION:\s*\w+.*?INPUT:.*?)(?=\nTHOUGHT:|\nACTION:|\nFINAL_ANSWER:|$)',
            clean, re.DOTALL | re.IGNORECASE
        )
        if fb:
            clean = fb.group(1).strip()
            cprint(C_WARN, "  [PARSER] Multi-step detected — truncated to first action")

    t = re.search(r'THOUGHT:\s*(.*?)(?=ACTION:|FINAL_ANSWER:)', clean,
                  re.DOTALL | re.IGNORECASE)
    if t:
        result["thought"] = t.group(1).strip()

    a = re.search(r'ACTION:\s*(\w+)', clean, re.IGNORECASE)
    i = re.search(
        r'INPUT:\s*(.*?)(?=\nTHOUGHT:|\nACTION:|\nFINAL_ANSWER:|\nOBSERVATION:|$)',
        clean, re.DOTALL | re.IGNORECASE
    )
    if a:
        result["action"] = a.group(1).strip()
    if i:
        result["input"] = i.group(1).strip()

    return result


# ── ReAct Loop ────────────────────────────────────────────────
def react_loop(task):
    cprint(C_HEAD, f"\n{'='*60}")
    cprint(C_HEAD, f"  AGENT-02  |  Model: {AGENT_MODEL}")
    cprint(C_HEAD, f"  Task: {task[:80]}")
    cprint(C_HEAD, f"{'='*60}\n")

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": (
            f"TASK: {task}\n\n"
            f"Output your FIRST action now — ONE THOUGHT, ONE ACTION, ONE INPUT.\n"
            f"Do NOT plan multiple steps.{FORMAT_REMINDER}"
        )}
    ]

    final_answer   = None
    iteration      = 0
    action_history = []

    while iteration < MAX_ITERATIONS:
        iteration += 1
        cprint(C_HEAD, f"\n{'-'*60}")
        cprint(C_HEAD, f"  Step {iteration}/{MAX_ITERATIONS}")
        cprint(C_HEAD, f"{'-'*60}")

        response = call_llm(messages)
        parsed   = parse_response(response)
        messages.append({"role": "assistant", "content": response})

        if parsed["final_answer"]:
            final_answer = parsed["final_answer"]
            cprint(C_HEAD, f"\n{'='*60}")
            cprint(C_HEAD, f"  COMPLETE — {iteration} steps")
            cprint(C_HEAD, f"{'='*60}")
            break

        if parsed["action"] and parsed["input"]:
            key          = f"{parsed['action']}::{parsed['input'][:120]}"
            repeat_count = action_history.count(key)

            if repeat_count >= 2:
                used   = set(h.split("::")[0] for h in action_history)
                unused = [x for x in ["rag_lookup","exploitdb","web_search","file_write"]
                          if x not in used]
                cprint(C_WARN, f"\n  [LOOP] Same action x{repeat_count+1} — forcing next step")
                messages.append({
                    "role": "user",
                    "content": (
                        f"You ran {parsed['action']} with this input {repeat_count+1} times. STOP.\n"
                        f"Unused tools: {unused if unused else ['file_write']}\n"
                        f"Move to next step now.{FORMAT_REMINDER}"
                    )
                })
                continue

            action_history.append(key)
            cprint(C_TOOL, f"\n  -> Executing: {parsed['action']}")
            observation = dispatch_tool(parsed["action"], parsed["input"])
            preview     = observation[:600] + ("..." if len(observation) > 600 else "")
            cprint(C_OBS, f"\n  [OBSERVATION]\n{preview}")
            # Determine the next expected step to guide the model
            steps_done = list(set(h.split("::")[0] for h in action_history))
            next_hint = ""
            if "shell" in steps_done and "rag_lookup" not in steps_done:
                next_hint = "\nNEXT STEP: rag_lookup — query KB for all found services."
            elif "rag_lookup" in steps_done and "exploitdb" not in steps_done:
                next_hint = "\nNEXT STEP: exploitdb — search postgresql 9.6 vulnerabilities."
            elif "exploitdb" in steps_done and "web_search" not in steps_done:
                next_hint = "\nNEXT STEP: web_search — NVD CVEs for postgresql 9.6."
            elif "web_search" in steps_done and "file_write" not in steps_done:
                next_hint = "\nNEXT STEP: file_write — save full markdown report."
            elif "file_write" in steps_done:
                next_hint = "\nNEXT STEP: write THOUGHT then FINAL_ANSWER: (all steps done)."

            messages.append({
                "role": "user",
                "content": (
                    f"OBSERVATION from {parsed['action']}:\n{observation}"
                    f"{next_hint}{FORMAT_REMINDER}"
                )
            })

        else:
            cprint(C_WARN, "  [PARSER] No action — requesting concise response")
            messages.append({
                "role": "user",
                "content": (
                    f"STOP THINKING. Output action NOW:\n"
                    f"THOUGHT: <one sentence>\n"
                    f"ACTION: <one of: {list(TOOLS.keys())}>\n"
                    f"INPUT: <input>\n"
                    f"Next step after nmap = rag_lookup. After rag_lookup = exploitdb.\n"
                    f"After exploitdb = web_search. After web_search = file_write.\n"
                    f"After file_write = FINAL_ANSWER:"
                )
            })

    if not final_answer:
        final_answer = f"Max iterations ({MAX_ITERATIONS}) reached. Check reports/ for output."
        cprint(C_WARN, "\n[!] Max iterations reached.")

    return final_answer


# ── Main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Agent-02 v4")
    parser.add_argument("task", nargs="?")
    parser.add_argument("--target", "-t")
    parser.add_argument("--interactive", "-i", action="store_true")
    parser.add_argument("--sudo-pass-file", "-p", default="", metavar="FILE")
    args = parser.parse_args()

    global SUDO_PASS
    if args.sudo_pass_file:
        pf = Path(args.sudo_pass_file).expanduser().resolve()
        if not pf.exists():
            print(f"[ERROR] Password file not found: {pf}")
            sys.exit(1)
        if pf.stat().st_mode & (stat.S_IRGRP | stat.S_IROTH):
            cprint(C_WARN, f"[WARNING] Fix permissions: chmod 600 {pf}")
        SUDO_PASS = pf.read_text().strip()
        if not SUDO_PASS:
            print(f"[ERROR] Password file empty: {pf}")
            sys.exit(1)
        print(f"[+] Sudo password loaded from: {pf}")

    if args.target:
        ts    = datetime.now().strftime('%Y%m%d_%H%M')
        fname = f"recon_{args.target.replace('.','_')}_{ts}.md"
        task  = (
            f"Perform full reconnaissance of target: {args.target}\n"
            f"Follow this exact workflow one step per response:\n"
            f"Step 1 — shell: nmap -sS -sV -sC --open {args.target}\n"
            f"Step 2 — rag_lookup: query KB for all found services in one call\n"
            f"Step 3 — exploitdb: search most critical service+version\n"
            f"Step 4 — web_search: NVD CVEs for most critical service\n"
            f"Step 5 — file_write: save full report as {fname}\n"
            f"Step 6 — write THOUGHT then FINAL_ANSWER: (NOT ACTION: FINAL_ANSWER)"
        )
    elif args.task:
        task = args.task
    elif args.interactive:
        print("\nAGENT-02 — Enter task:")
        task = input("> ").strip()
        if not task:
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(0)

    result = react_loop(task)
    cprint(C_HEAD, f"\n{'='*60}\nFINAL SUMMARY:\n{'='*60}")
    print(result)


if __name__ == "__main__":
    main()
