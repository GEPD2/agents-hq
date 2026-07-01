#!/usr/bin/env python3
"""
AGENTS-HQ — Agent-06 Ghidra Reverse Engineering Agent
Autonomous malware analysis and binary reverse engineering platform

Scan Modes:
  --mode fast     — hash + strings + PE analysis + IOC extraction
  --mode deep     — full pipeline, all tools, no emulation
  --mode insane   — scorched earth, max function depth, full dossier

Intelligence Pipeline:
  binary_info     — file type, entropy, packer/protector detection (DIE)
  hash_compute    — MD5/SHA1/SHA256/SHA512/SSDEEP + instant VT lookup
  vt_check        — VirusTotal hash reputation, AV detections, malware family
  pe_analysis     — PE header, imports, exports, sections, anomalies (pefile)
  strings_extract — static string extraction, IOC-filtered and categorized
  ioc_extract     — regex engine → IPs, domains, URLs, registry keys, mutexes, C2s
  ghidra_decompile— headless Ghidra → decompiled pseudocode per function
  function_map    — call graph analysis, suspicious API mapping, MITRE ATT&CK hints
  yara_generate   — auto-generate YARA rule from unique strings + byte patterns
  rag_ingest      — push all findings into ChromaDB security_docs collection
  file_write      — structured RE report (.md) + YARA rule (.yar)

Usage:
  python3 agent_06_ghidra.py --target /path/to/binary --mode fast
  python3 agent_06_ghidra.py --target /path/to/malware.exe --mode deep
  python3 agent_06_ghidra.py --target /path/to/sample --mode insane
  python3 agent_06_ghidra.py --hash <sha256> --mode fast
  python3 agent_06_ghidra.py --interactive
  python3 agent_06_ghidra.py --n8n-server
"""

import sys, json, subprocess, argparse, requests, re, os, hashlib, math
import struct, socket, time, tempfile, shutil
from datetime import datetime
from pathlib import Path
from collections import Counter

# ── Config ────────────────────────────────────────────────────
OLLAMA_HOST      = "localhost"
OLLAMA_PORT      = 11434
AGENT_MODEL      = "qwen2.5:14b"
CHROMA_HOST      = "localhost"
CHROMA_PORT      = 8000
REPORTS_DIR      = Path(__file__).parent.parent / "reports"
YARA_DIR         = Path(__file__).parent.parent / "yara"
GHIDRA_PROJECTS  = Path(__file__).parent / "ghidra_projects"
TIMEOUT_WEB      = 25
TIMEOUT_GHIDRA   = 300   # 5 min per analysis
N8N_WEBHOOK_PORT = int(os.environ.get("N8N_WEBHOOK_PORT", "8766"))

# Ghidra auto-detection paths (common install locations)
GHIDRA_SEARCH_PATHS = [
    "/opt/ghidra",
    "/usr/local/ghidra",
    "/usr/share/ghidra",
    Path.home() / "ghidra",
    Path.home() / "tools" / "ghidra",
    Path.home() / "Desktop" / "ghidra",
    "/opt/tools/ghidra",
]

# Mode iteration limits
MODE_LIMITS = {
    "fast":   12,
    "deep":   20,
    "insane": 35,
}

MODE_LABELS = {
    "fast":   "⚡ FAST ANALYSIS",
    "deep":   "🔬 DEEP RE",
    "insane": "☠  INSANE — FULL DOSSIER",
}

MODE_WORKFLOWS = {
    "fast":   ["binary_info","hash_compute","vt_check","strings_extract",
               "ioc_extract","file_write"],
    "deep":   ["binary_info","hash_compute","vt_check","pe_analysis",
               "strings_extract","ioc_extract","ghidra_decompile",
               "function_map","yara_generate","rag_ingest","file_write"],
    "insane": ["binary_info","hash_compute","vt_check","pe_analysis",
               "strings_extract","ioc_extract","ghidra_decompile",
               "function_map","ghidra_decompile","function_map",
               "yara_generate","rag_ingest","file_write"],
}

# ── ANSI Colors ───────────────────────────────────────────────
C_THINK  = "\033[38;5;244m"
C_HEAD   = "\033[38;5;208m"   # orange for RE agent
C_TOOL   = "\033[38;5;226m"
C_OBS    = "\033[38;5;82m"
C_WARN   = "\033[38;5;196m"
C_ACT    = "\033[38;5;39m"
C_INFO   = "\033[38;5;51m"
C_RESET  = "\033[0m"

MODE_COLORS = {
    "fast":   "\033[38;5;82m",
    "deep":   "\033[38;5;208m",
    "insane": "\033[38;5;196m",
}

def cprint(color, text, end="\n"):
    print(f"{color}{text}{C_RESET}", end=end, flush=True)

# ── API Keys ──────────────────────────────────────────────────
def load_env():
    env_file = Path(__file__).parent / ".env"
    if not env_file.exists():
        # Try parent agent_01_osint directory
        env_file = Path(__file__).parent.parent / "agent_01_osint" / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                os.environ.setdefault(k.strip(), v.strip())

load_env()
VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

FORMAT_REMINDER = (
    "\n\nFORMAT REMINDER:\n"
    "  Tool: THOUGHT: ... | ACTION: <toolname> | INPUT: ...\n"
    "  Done: THOUGHT: ... | FINAL_ANSWER: ...\n"
    "  Keep thinking SHORT — 3-4 sentences max then write action immediately."
)

# ══════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════

def find_ghidra():
    """Auto-detect Ghidra installation, return path to analyzeHeadless."""
    # Check PATH first
    which = shutil.which("analyzeHeadless")
    if which:
        return which
    # Search known paths
    for base in GHIDRA_SEARCH_PATHS:
        base = Path(base)
        if base.exists():
            matches = list(base.rglob("analyzeHeadless"))
            if matches:
                return str(matches[0])
            # Also check support/analyzeHeadless pattern
            matches = list(base.rglob("support/analyzeHeadless"))
            if matches:
                return str(matches[0])
    return None

def compute_entropy(data):
    """Shannon entropy of bytes."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = -sum((c/length) * math.log2(c/length) for c in counts.values() if c > 0)
    return round(entropy, 4)

def is_pe(data):
    """Check if bytes look like a PE file."""
    return len(data) > 2 and data[:2] == b'MZ'

def is_elf(data):
    """Check if bytes look like an ELF file."""
    return len(data) > 4 and data[:4] == b'\x7fELF'

# ══════════════════════════════════════════════════════════════
# TOOLS
# ══════════════════════════════════════════════════════════════

def tool_binary_info(filepath):
    cprint(C_TOOL, f"  [BINARY_INFO] {filepath}")
    path = Path(filepath)
    if not path.exists():
        return f"[BINARY_INFO] File not found: {filepath}"
    try:
        data = path.read_bytes()
        size = len(data)
        entropy = compute_entropy(data)

        out = [f"[BINARY_INFO] {path.name}:"]
        out.append(f"  Size     : {size:,} bytes ({size/1024:.1f} KB)")
        out.append(f"  Entropy  : {entropy} {'⚠ HIGH (packed/encrypted?)' if entropy > 7.0 else '✓ normal'}")

        # File type via `file` command
        try:
            r = subprocess.run(["file", "-b", str(path)],
                               capture_output=True, text=True, timeout=10)
            out.append(f"  File type: {r.stdout.strip()}")
        except Exception:
            pass

        # Magic bytes identification
        magic = data[:8].hex()
        out.append(f"  Magic    : {magic}")
        if is_pe(data):
            out.append(f"  Format   : PE (Windows Executable)")
            # PE bitness
            if len(data) > 0x3C + 4:
                pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
                if pe_offset + 6 < len(data):
                    machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
                    arch_map = {0x014c: "x86 (32-bit)", 0x8664: "x86-64 (64-bit)",
                               0x01c0: "ARM", 0xaa64: "ARM64"}
                    out.append(f"  Arch     : {arch_map.get(machine, f'Unknown (0x{machine:04x})')}")
        elif is_elf(data):
            out.append(f"  Format   : ELF (Linux/Unix)")
            if len(data) > 5:
                bits = "64-bit" if data[4] == 2 else "32-bit"
                endian = "little-endian" if data[5] == 1 else "big-endian"
                out.append(f"  Arch     : ELF {bits} {endian}")
        elif data[:4] == b'%PDF':
            out.append(f"  Format   : PDF document")
        elif data[:2] == b'PK':
            out.append(f"  Format   : ZIP/JAR/APK/DOCX archive")
        elif data[:4] == b'\xca\xfe\xba\xbe':
            out.append(f"  Format   : Mach-O (macOS)")

        # DIE (Detect-It-Easy) packer detection
        die_path = shutil.which("die") or shutil.which("diec")
        if die_path:
            try:
                r = subprocess.run([die_path, str(path)],
                                   capture_output=True, text=True, timeout=20)
                if r.stdout.strip():
                    out.append(f"\n  DIE Analysis:")
                    for line in r.stdout.strip().split('\n')[:10]:
                        out.append(f"    {line}")
            except Exception:
                pass
        else:
            # Manual packer heuristics
            out.append(f"\n  Packer hints (DIE not installed):")
            packer_sigs = {
                b'UPX0': 'UPX packer', b'UPX1': 'UPX packer',
                b'MPRESS1': 'MPRESS', b'MPRESS2': 'MPRESS',
                b'.aspack': 'ASPack', b'PECompact': 'PECompact',
                b'Themida': 'Themida protector',
                b'VMProtect': 'VMProtect',
                b'NSPack': 'NSPack',
            }
            found_packers = []
            for sig, name in packer_sigs.items():
                if sig in data:
                    found_packers.append(name)
            if found_packers:
                out.append(f"    ⚠ Detected: {', '.join(found_packers)}")
            else:
                out.append(f"    No known packer signatures found")

        # Section entropy hints
        if entropy > 7.2:
            out.append(f"\n  ⚠ HIGH ENTROPY WARNING: Binary likely packed, encrypted, or obfuscated")
            out.append(f"    Ghidra decompilation may yield limited results on packed sections")

        return "\n".join(out)
    except Exception as e:
        return f"[BINARY_INFO] Error: {e}"


def tool_hash_compute(filepath):
    cprint(C_TOOL, f"  [HASH] {filepath}")
    path = Path(filepath)
    if not path.exists():
        return f"[HASH] File not found: {filepath}"
    try:
        data = path.read_bytes()
        md5    = hashlib.md5(data).hexdigest()
        sha1   = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        sha512 = hashlib.sha512(data).hexdigest()

        out = [f"[HASH] {path.name}:"]
        out.append(f"  MD5    : {md5}")
        out.append(f"  SHA1   : {sha1}")
        out.append(f"  SHA256 : {sha256}")
        out.append(f"  SHA512 : {sha512[:64]}...{sha512[-8:]}")

        # SSDEEP fuzzy hash
        ssdeep_path = shutil.which("ssdeep")
        if ssdeep_path:
            try:
                r = subprocess.run([ssdeep_path, str(path)],
                                   capture_output=True, text=True, timeout=15)
                lines = [l for l in r.stdout.strip().split('\n') if path.name in l or ',' in l]
                if lines:
                    out.append(f"  SSDEEP : {lines[0].split(',')[0]}")
            except Exception:
                pass

        # Quick VT check via hash
        if VIRUSTOTAL_KEY:
            try:
                r = requests.get(
                    f"https://www.virustotal.com/api/v3/files/{sha256}",
                    headers={"x-apikey": VIRUSTOTAL_KEY, "User-Agent": "AGENTS-HQ/2.0"},
                    timeout=TIMEOUT_WEB)
                if r.status_code == 200:
                    d = r.json().get("data", {}).get("attributes", {})
                    stats = d.get("last_analysis_stats", {})
                    mal   = stats.get("malicious", 0)
                    sus   = stats.get("suspicious", 0)
                    total = sum(stats.values())
                    family = d.get("popular_threat_classification", {}).get("suggested_threat_label", "")
                    out.append(f"\n  VT Quick: {mal}/{total} malicious | {sus} suspicious")
                    if family:
                        out.append(f"  Malware family: {family}")
                    if mal == 0:
                        out.append(f"  VT Status: ✓ Clean or unknown sample")
                    else:
                        out.append(f"  VT Status: ⚠ DETECTED — proceed with caution")
                elif r.status_code == 404:
                    out.append(f"\n  VT Quick: Hash not found in VirusTotal (new/unknown sample)")
            except Exception as e:
                out.append(f"\n  VT Quick: Error — {e}")

        return "\n".join(out)
    except Exception as e:
        return f"[HASH] Error: {e}"


def tool_vt_check(filepath_or_hash):
    cprint(C_TOOL, f"  [VIRUSTOTAL] {filepath_or_hash}")
    if not VIRUSTOTAL_KEY:
        return "[VIRUSTOTAL] No API key — set VIRUSTOTAL_API_KEY in .env"
    # If it's a file path, compute SHA256
    filepath_or_hash = filepath_or_hash.strip().split()[0]
    sha256 = filepath_or_hash
    filename = filepath_or_hash
    path = Path(filepath_or_hash)
    if path.exists():
        data   = path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        filename = path.name
    elif re.match(r'^[a-fA-F0-9]{32,64}$', filepath_or_hash):
        sha256 = filepath_or_hash
    else:
        return f"[VIRUSTOTAL] Input must be a file path or hash (MD5/SHA1/SHA256)"

    headers = {"x-apikey": VIRUSTOTAL_KEY, "User-Agent": "AGENTS-HQ/2.0"}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                         headers=headers, timeout=TIMEOUT_WEB)
        if r.status_code == 404:
            return f"[VIRUSTOTAL] {sha256[:16]}... — NOT FOUND in VirusTotal (0-day or private sample)"
        if r.status_code == 429:
            return "[VIRUSTOTAL] Rate limited (4 req/min free tier)"
        if r.status_code != 200:
            return f"[VIRUSTOTAL] Status {r.status_code}: {r.text[:200]}"

        d    = r.json().get("data", {})
        attr = d.get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        mal   = stats.get("malicious", 0)
        sus   = stats.get("suspicious", 0)
        harm  = stats.get("harmless", 0)
        undet = stats.get("undetected", 0)
        total = sum(stats.values())

        out = [f"[VIRUSTOTAL] {filename} ({sha256[:16]}...):"]
        out.append(f"  Detections   : {mal}/{total} malicious | {sus} suspicious | {harm} harmless")
        out.append(f"  Reputation   : {attr.get('reputation', 0)}")

        # Threat classification
        tc = attr.get("popular_threat_classification", {})
        if tc:
            label = tc.get("suggested_threat_label", "")
            cats  = [c.get("value","") for c in tc.get("popular_threat_category", [])[:3]]
            names = [n.get("value","") for n in tc.get("popular_threat_name", [])[:5]]
            if label: out.append(f"  Threat label : {label}")
            if cats:  out.append(f"  Categories   : {', '.join(cats)}")
            if names: out.append(f"  Threat names : {', '.join(names)}")

        # Tags
        tags = attr.get("tags", [])
        if tags:
            out.append(f"  Tags         : {', '.join(tags[:12])}")

        # Sigma analysis
        sigma = attr.get("sigma_analysis_stats", {})
        if sigma:
            out.append(f"  Sigma rules  : critical={sigma.get('critical',0)} "
                       f"high={sigma.get('high',0)} medium={sigma.get('medium',0)}")

        # Sandbox behaviour summary
        sandbox = attr.get("sandbox_verdicts", {})
        if sandbox:
            out.append(f"\n  Sandbox verdicts:")
            for engine, verdict in list(sandbox.items())[:5]:
                cat = verdict.get("category","")
                mal_names = verdict.get("malware_names", [])
                out.append(f"    {engine}: {cat} {mal_names[:2]}")

        # Top AV detections
        results = attr.get("last_analysis_results", {})
        detections = [(eng, res.get("result","")) for eng, res in results.items()
                      if res.get("category") == "malicious"]
        if detections:
            out.append(f"\n  AV Detections ({len(detections)} engines):")
            for eng, result in detections[:10]:
                out.append(f"    {eng:25s} → {result}")

        # File info
        if attr.get("magic"):
            out.append(f"\n  Magic        : {attr['magic'][:80]}")
        if attr.get("size"):
            out.append(f"  Size         : {attr['size']:,} bytes")
        if attr.get("first_submission_date"):
            out.append(f"  First seen   : {datetime.fromtimestamp(attr['first_submission_date'])}")
        if attr.get("last_submission_date"):
            out.append(f"  Last seen    : {datetime.fromtimestamp(attr['last_submission_date'])}")

        return "\n".join(out)
    except Exception as e:
        return f"[VIRUSTOTAL] Error: {e}"


def tool_pe_analysis(filepath):
    cprint(C_TOOL, f"  [PE_ANALYSIS] {filepath}")
    path = Path(filepath)
    if not path.exists():
        return f"[PE_ANALYSIS] File not found: {filepath}"
    data = path.read_bytes()
    if not is_pe(data):
        if is_elf(data):
            return tool_elf_analysis(filepath, data)
        return f"[PE_ANALYSIS] Not a PE file — detected as ELF or unknown format"
    try:
        import pefile
        pe = pefile.PE(data=data)
        out = [f"[PE_ANALYSIS] {path.name}:"]

        # Header info
        machine = pe.FILE_HEADER.Machine
        arch_map = {0x014c: "x86", 0x8664: "x86-64", 0x01c0: "ARM", 0xaa64: "ARM64"}
        out.append(f"  Architecture  : {arch_map.get(machine, f'0x{machine:04x}')}")
        out.append(f"  Compile time  : {datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)}")
        out.append(f"  Subsystem     : {pe.OPTIONAL_HEADER.Subsystem} "
                   f"({'GUI' if pe.OPTIONAL_HEADER.Subsystem == 2 else 'Console/DLL/other'})")
        out.append(f"  Entry point   : 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}")
        out.append(f"  Image base    : 0x{pe.OPTIONAL_HEADER.ImageBase:016x}")

        # Sections
        out.append(f"\n  Sections ({len(pe.sections)}):")
        for sec in pe.sections:
            name = sec.Name.decode('utf-8', errors='replace').strip('\x00')
            raw  = sec.SizeOfRawData
            virt = sec.Misc_VirtualSize
            ent  = compute_entropy(sec.get_data())
            rwx  = ""
            chars = sec.Characteristics
            if chars & 0x20000000: rwx += "E"
            if chars & 0x40000000: rwx += "R"
            if chars & 0x80000000: rwx += "W"
            flag = " ⚠ HIGH ENTROPY" if ent > 7.0 else ""
            flag += " ⚠ WX (shellcode?)" if "EW" in rwx or "ERW" in rwx else ""
            out.append(f"    {name:<12} VA=0x{sec.VirtualAddress:08x} "
                       f"raw={raw:6,}b  virt={virt:6,}b  "
                       f"entropy={ent}  [{rwx}]{flag}")

        # Imports (grouped by DLL)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            out.append(f"\n  Imports:")
            suspicious_apis = {
                # Process injection
                "VirtualAllocEx","WriteProcessMemory","CreateRemoteThread",
                "NtCreateThreadEx","RtlCreateUserThread","SetThreadContext",
                "QueueUserAPC","NtUnmapViewOfSection",
                # Privilege escalation
                "AdjustTokenPrivileges","OpenProcessToken","LookupPrivilegeValue",
                # Anti-analysis / evasion
                "IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess",
                "GetTickCount","QueryPerformanceCounter","Sleep","NtDelayExecution",
                "GetSystemInfo","EnumProcesses",
                # Network
                "WSAStartup","connect","send","recv","WinHttpOpen","InternetOpenUrl",
                "URLDownloadToFile","HttpSendRequest",
                # Persistence
                "RegSetValueEx","RegOpenKeyEx","CreateService","StartService",
                "SHGetSpecialFolderPath","GetStartupInfo",
                # Crypto
                "CryptEncrypt","CryptDecrypt","CryptImportKey","BCryptEncrypt",
                # File ops (ransomware)
                "MoveFileEx","DeleteFileW","FindFirstFileW","SetFileAttributes",
                # Keylogging / screenshots
                "SetWindowsHookEx","GetAsyncKeyState","BitBlt","GetDC",
            }
            flagged = []
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('utf-8', errors='replace')
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        fname = imp.name.decode('utf-8', errors='replace')
                        funcs.append(fname)
                        if fname in suspicious_apis:
                            flagged.append(f"{dll}::{fname}")
                out.append(f"    {dll} ({len(funcs)} functions)")
                if len(funcs) <= 8:
                    out.append(f"      {', '.join(funcs)}")
                else:
                    out.append(f"      {', '.join(funcs[:8])} ... +{len(funcs)-8} more")

            if flagged:
                out.append(f"\n  ⚠ SUSPICIOUS IMPORTS ({len(flagged)} flagged):")
                for f in flagged:
                    out.append(f"    → {f}")

        # Exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            exports = [exp.name.decode('utf-8', errors='replace')
                       for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols
                       if exp.name]
            out.append(f"\n  Exports ({len(exports)}):")
            for exp in exports[:20]:
                out.append(f"    {exp}")

        # Resources
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            out.append(f"\n  Resources:")
            for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries[:8]:
                try:
                    res_name = pefile.RESOURCE_TYPE.get(res_type.struct.Id, str(res_type.struct.Id))
                    out.append(f"    Type: {res_name}")
                except Exception:
                    pass

        # Anomaly detection
        anomalies = []
        if pe.FILE_HEADER.TimeDateStamp == 0:
            anomalies.append("Compile timestamp zeroed (anti-forensics)")
        if pe.FILE_HEADER.TimeDateStamp > int(time.time()):
            anomalies.append("Future compile timestamp (forged)")
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            anomalies.append("No imports (shellcode/packed/manually loaded)")
        if anomalies:
            out.append(f"\n  ⚠ ANOMALIES:")
            for a in anomalies:
                out.append(f"    → {a}")

        pe.close()
        return "\n".join(out)

    except ImportError:
        return ("[PE_ANALYSIS] pefile not installed.\n"
                "Install: pip install pefile --break-system-packages\n"
                "Falling back to manual PE parsing...")
    except Exception as e:
        return f"[PE_ANALYSIS] Error: {e}"


def tool_elf_analysis(filepath, data=None):
    """ELF binary analysis fallback when pefile not applicable."""
    path = Path(filepath)
    if data is None:
        data = path.read_bytes()
    out = [f"[ELF_ANALYSIS] {path.name}:"]
    # ELF header fields
    bits     = "64-bit" if data[4] == 2 else "32-bit"
    endian   = "little-endian" if data[5] == 1 else "big-endian"
    elf_type = {1:"REL (relocatable)", 2:"EXEC (executable)",
                3:"DYN (shared object)", 4:"CORE"}.get(
                struct.unpack_from('<H' if data[5]==1 else '>H', data, 0x10)[0], "unknown")
    out.append(f"  Format   : ELF {bits} {endian}")
    out.append(f"  Type     : {elf_type}")
    # Strings via readelf
    try:
        r = subprocess.run(["readelf", "-d", str(path)],
                           capture_output=True, text=True, timeout=15)
        for line in r.stdout.split('\n'):
            if 'NEEDED' in line or 'SONAME' in line or 'RPATH' in line:
                out.append(f"  {line.strip()}")
    except Exception:
        pass
    return "\n".join(out)


def tool_strings_extract(filepath):
    cprint(C_TOOL, f"  [STRINGS] {filepath}")
    path = Path(filepath)
    if not path.exists():
        return f"[STRINGS] File not found: {filepath}"
    try:
        data = path.read_bytes()
        # Extract printable ASCII strings (min 4 chars)
        pattern = re.compile(rb'[\x20-\x7e]{4,}')
        raw_strings = [s.decode('ascii') for s in pattern.findall(data)]

        # Unicode strings (UTF-16 LE)
        pattern_u = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')
        unicode_raw = pattern_u.findall(data)
        unicode_strings = [s.decode('utf-16-le', errors='replace').strip()
                          for s in unicode_raw]

        all_strings = list(set(raw_strings + unicode_strings))
        out = [f"[STRINGS] {path.name}: {len(all_strings)} strings extracted"]

        # Categorize strings
        categories = {
            "network":    [],
            "filesystem": [],
            "registry":   [],
            "crypto":     [],
            "evasion":    [],
            "injection":  [],
            "c2_hints":   [],
            "interesting":[],
        }

        net_patterns = [r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                        r'https?://', r'[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}',
                        r':\d{2,5}', r'User-Agent:', r'Content-Type:',
                        r'POST|GET|HTTP/']
        fs_patterns  = [r'C:\\', r'%[A-Z]+%', r'\\AppData\\', r'\\Temp\\',
                        r'\.exe$', r'\.dll$', r'\.bat$', r'\.ps1$', r'\.vbs$',
                        r'\\System32\\', r'\\ProgramData\\']
        reg_patterns = [r'HKEY_', r'HKLM\\', r'HKCU\\', r'SOFTWARE\\',
                        r'CurrentVersion\\Run', r'\\Services\\']
        crypto_kw    = ['AES','RSA','RC4','MD5','SHA','encrypt','decrypt',
                        'base64','key','iv','cipher','ransom','bitcoin','wallet']
        evasion_kw   = ['IsDebuggerPresent','VirtualBox','VMware','sandbox',
                        'analysis','wireshark','procmon','x64dbg','ollydbg',
                        'CheckRemoteDebugger','NtQueryInformation','GetTickCount']
        inject_kw    = ['VirtualAllocEx','WriteProcessMemory','CreateRemoteThread',
                        'NtCreateThread','shellcode','inject','hook','SetWindowsHook']
        interesting_kw=['password','passwd','secret','token','api_key','auth',
                        'admin','root','cmd.exe','powershell','wget','curl',
                        'cmd /c','wscript','cscript','mshta','regsvr32']

        for s in all_strings:
            sl = s.lower()
            if any(re.search(p, s, re.IGNORECASE) for p in net_patterns):
                categories["network"].append(s)
            if any(re.search(p, s, re.IGNORECASE) for p in fs_patterns):
                categories["filesystem"].append(s)
            if any(re.search(p, s, re.IGNORECASE) for p in reg_patterns):
                categories["registry"].append(s)
            if any(kw.lower() in sl for kw in crypto_kw):
                categories["crypto"].append(s)
            if any(kw.lower() in sl for kw in evasion_kw):
                categories["evasion"].append(s)
            if any(kw.lower() in sl for kw in inject_kw):
                categories["injection"].append(s)
            if any(kw.lower() in sl for kw in interesting_kw):
                categories["interesting"].append(s)

        # C2 hints — IPs + domains that look suspicious
        for s in categories["network"]:
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
                octets = list(map(int, re.findall(r'\d+', s)[:4]))
                if not (octets[0] in [10,127,172,192,224,255]):
                    categories["c2_hints"].append(f"[PUBLIC IP] {s}")
            elif re.match(r'[a-zA-Z0-9\-]+\.[a-zA-Z]{2,6}$', s) and '.' in s:
                if len(s) > 8 and not any(kw in s.lower() for kw in
                   ['microsoft','windows','google','apple','mozilla','adobe']):
                    categories["c2_hints"].append(f"[DOMAIN] {s}")

        for cat, items in categories.items():
            if items:
                unique = list(dict.fromkeys(items))  # preserve order, deduplicate
                out.append(f"\n  [{cat.upper()}] ({len(unique)} strings):")
                for s in unique[:20]:
                    out.append(f"    {s[:120]}")
                if len(unique) > 20:
                    out.append(f"    ... +{len(unique)-20} more")

        return "\n".join(out)
    except Exception as e:
        return f"[STRINGS] Error: {e}"


def tool_ioc_extract(filepath):
    cprint(C_TOOL, f"  [IOC_EXTRACT] {filepath}")
    path = Path(filepath)
    if not path.exists():
        return f"[IOC_EXTRACT] File not found: {filepath}"
    try:
        data = path.read_bytes()
        # Decode as latin-1 for full byte coverage
        text = data.decode('latin-1')

        iocs = {
            "ipv4":     [],
            "ipv6":     [],
            "domains":  [],
            "urls":     [],
            "emails":   [],
            "registry": [],
            "mutexes":  [],
            "files":    [],
            "hashes":   [],
            "cves":     [],
            "btc":      [],
        }

        # IPv4 (exclude private/loopback)
        for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
            try:
                parts = list(map(int, ip.split('.')))
                if all(0 <= p <= 255 for p in parts):
                    if not (parts[0] in [10,127,169,172,192,224,255,0]
                            or (parts[0]==172 and 16<=parts[1]<=31)
                            or (parts[0]==192 and parts[1]==168)):
                        iocs["ipv4"].append(ip)
            except Exception:
                pass

        # IPv6
        ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        iocs["ipv6"] = list(set(re.findall(ipv6_pattern, text)))[:10]

        # URLs
        for url in re.findall(r'https?://[^\s\x00-\x1f"\'<>]{6,}', text):
            iocs["urls"].append(url[:150])

        # Domains (suspicious — not Microsoft/Windows/Google)
        whitelist = ['microsoft','windows','google','mozilla','apple',
                     'cloudflare','amazon','github','stackoverflow']
        for dom in re.findall(r'\b(?:[a-zA-Z0-9\-]{2,63}\.)+(?:com|net|org|io|ru|cn|tk|top|xyz|pw|cc|biz|info|onion)\b', text):
            if not any(w in dom.lower() for w in whitelist) and len(dom) > 6:
                iocs["domains"].append(dom)

        # Registry keys
        iocs["registry"] = list(set(re.findall(
            r'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\[^\x00\n"\']{4,80}', text)))[:20]

        # Mutex patterns
        iocs["mutexes"] = list(set(re.findall(
            r'(?:mutex|Mutex|MUTEX)[^\x00\n"\']{2,40}', text, re.IGNORECASE)))[:10]

        # File paths (Windows)
        iocs["files"] = list(set(re.findall(
            r'[A-Za-z]:\\(?:[^\\/:*?"<>|\x00\n]{1,50}\\)*[^\\/:*?"<>|\x00\n]{1,50}', text)))[:20]

        # Hashes (MD5/SHA1/SHA256)
        iocs["hashes"] = list(set(re.findall(r'\b[a-fA-F0-9]{32,64}\b', text)))[:15]

        # CVEs
        iocs["cves"] = list(set(re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)))

        # Bitcoin addresses
        iocs["btc"] = list(set(re.findall(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', text)))[:5]

        # Deduplicate
        for k in iocs:
            iocs[k] = list(dict.fromkeys(iocs[k]))

        out = [f"[IOC_EXTRACT] {path.name}:"]
        total = sum(len(v) for v in iocs.values())
        out.append(f"  Total IOCs found: {total}")

        for category, items in iocs.items():
            if items:
                out.append(f"\n  {category.upper()} ({len(items)}):")
                for item in items[:15]:
                    out.append(f"    {str(item)[:120]}")

        return "\n".join(out)
    except Exception as e:
        return f"[IOC_EXTRACT] Error: {e}"


def tool_ghidra_decompile(filepath):
    cprint(C_TOOL, f"  [GHIDRA] Decompiling {filepath}")
    path = Path(filepath)
    if not path.exists():
        return f"[GHIDRA] File not found: {filepath}"

    analyze_headless = find_ghidra()
    if not analyze_headless:
        return ("[GHIDRA] analyzeHeadless not found.\n"
                "Ensure Ghidra is installed and set GHIDRA_HOME or add to PATH.\n"
                "Common paths checked: /opt/ghidra, ~/ghidra, /usr/local/ghidra\n"
                "Manual: export PATH=$PATH:/path/to/ghidra/support")

    GHIDRA_PROJECTS.mkdir(parents=True, exist_ok=True)
    ts         = datetime.now().strftime('%Y%m%d_%H%M%S')
    project    = f"re_{ts}"
    proj_dir   = GHIDRA_PROJECTS / project
    script_dir = Path(__file__).parent / "ghidra_scripts"
    script_dir.mkdir(exist_ok=True)

    # Write decompile script
    script_path = script_dir / "DecompileAll.java"
    script_path.write_text("""
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.*;

public class DecompileAll extends GhidraScript {
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator functions = fm.getFunctions(true);
        int count = 0;
        int maxFunctions = 50;
        File outFile = new File(System.getProperty("ghidra.out", "/tmp/ghidra_decomp.txt"));
        PrintWriter pw = new PrintWriter(new FileWriter(outFile));
        pw.println("=== GHIDRA DECOMPILATION: " + currentProgram.getName() + " ===");
        pw.println("Total functions: " + fm.getFunctionCount());
        pw.println();
        while (functions.hasNext() && count < maxFunctions) {
            Function func = functions.next();
            if (func.isThunk()) continue;
            DecompileResults results = decomp.decompileFunction(func, 30,
                new ConsoleTaskMonitor());
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                pw.println("// Function: " + func.getName() +
                           " @ " + func.getEntryPoint());
                pw.println("// Size: " + func.getBody().getNumAddresses() + " instructions");
                pw.println(code);
                pw.println("---");
                count++;
            }
        }
        pw.println("\\n=== DECOMPILED " + count + " FUNCTIONS ===");
        pw.close();
        decomp.dispose();
        println("Decompiled " + count + " functions to " + outFile.getPath());
    }
}
""")

    out_file = Path(f"/tmp/ghidra_decomp_{ts}.txt")
    cprint(C_INFO, f"  [GHIDRA] Running headless analysis — this takes 1-3 minutes...")
    cprint(C_INFO, f"  [GHIDRA] Script: {script_path}")
    cprint(C_INFO, f"  [GHIDRA] Output: {out_file}")

    try:
        cmd = [
            analyze_headless,
            str(proj_dir),
            project,
            "-import", str(path),
            "-scriptPath", str(script_dir),
            "-postScript", "DecompileAll.java",
            "-scriptlog", str(Path(f"/tmp/ghidra_log_{ts}.txt")),
            "-deleteProject",
            "-noanalysis" if path.stat().st_size < 1000 else "",
        ]
        cmd = [c for c in cmd if c]  # remove empty strings

        env = os.environ.copy()
        env["ghidra.out"] = str(out_file)

        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=TIMEOUT_GHIDRA, env=env)

        if out_file.exists() and out_file.stat().st_size > 100:
            content = out_file.read_text(errors='replace')
            # Truncate if massive
            if len(content) > 15000:
                # Keep first 8000 and last 3000
                content = content[:8000] + "\n\n...[TRUNCATED]...\n\n" + content[-3000:]
            out_file.unlink(missing_ok=True)
            return f"[GHIDRA] Decompilation complete:\n{content}"
        else:
            stderr = proc.stderr[-2000:] if proc.stderr else ""
            stdout = proc.stdout[-1000:] if proc.stdout else ""
            return (f"[GHIDRA] Analysis ran but output missing.\n"
                    f"Return code: {proc.returncode}\n"
                    f"Stderr (last 2000): {stderr}\n"
                    f"Stdout (last 1000): {stdout}")

    except subprocess.TimeoutExpired:
        return f"[GHIDRA] Timed out after {TIMEOUT_GHIDRA}s — binary may be too large or complex"
    except Exception as e:
        return f"[GHIDRA] Error: {e}"
    finally:
        # Cleanup project dir
        if proj_dir.exists():
            shutil.rmtree(str(proj_dir), ignore_errors=True)


def tool_function_map(filepath):
    cprint(C_TOOL, f"  [FUNCTION_MAP] {filepath}")
    path = Path(filepath)
    if not path.exists():
        return f"[FUNCTION_MAP] File not found: {filepath}"

    out = [f"[FUNCTION_MAP] {path.name}:"]

    # Use nm for symbol table
    try:
        r = subprocess.run(["nm", "-D", str(path)],
                           capture_output=True, text=True, timeout=15)
        if r.returncode == 0 and r.stdout.strip():
            lines = r.stdout.strip().split('\n')
            out.append(f"\n  Dynamic symbols ({len(lines)}):")
            for line in lines[:30]:
                out.append(f"    {line}")
    except Exception:
        pass

    # Use objdump for imports
    try:
        r = subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(path)],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            # Count functions and find suspicious calls
            func_calls = re.findall(r'call\s+[0-9a-fA-F]+\s+<([^>]+)>', r.stdout)
            call_counter = Counter(func_calls)
            out.append(f"\n  Function calls ({len(call_counter)} unique):")

            # MITRE ATT&CK API mapping
            mitre_map = {
                # T1055 - Process Injection
                "VirtualAllocEx":       "T1055 Process Injection",
                "WriteProcessMemory":   "T1055 Process Injection",
                "CreateRemoteThread":   "T1055.001 Thread Injection",
                "NtCreateThreadEx":     "T1055.001 Thread Injection",
                "SetThreadContext":     "T1055.003 Thread Hijacking",
                "QueueUserAPC":         "T1055.004 APC Injection",
                # T1059 - Command Execution
                "ShellExecute":         "T1059 Command Execution",
                "WinExec":              "T1059 Command Execution",
                "CreateProcess":        "T1059 Command Execution",
                "system":               "T1059 Command Execution",
                # T1082 - System Discovery
                "GetSystemInfo":        "T1082 System Discovery",
                "GetComputerName":      "T1082 System Discovery",
                "GetUserName":          "T1082 System Discovery",
                # T1083 - File Discovery
                "FindFirstFile":        "T1083 File Discovery",
                # T1112 - Registry
                "RegSetValueEx":        "T1112 Registry Modification",
                "RegOpenKeyEx":         "T1112 Registry Modification",
                # T1547 - Boot Persistence
                "CreateService":        "T1547.003 Persistence via Service",
                # T1027 - Obfuscation
                "CryptEncrypt":         "T1027/T1486 Encryption",
                "BCryptEncrypt":        "T1027/T1486 Encryption",
                # T1071 - C2
                "WSAConnect":           "T1071 C2 Communication",
                "connect":              "T1071 C2 Communication",
                "send":                 "T1071 C2 Data Exfil",
                "InternetOpenUrl":      "T1071.001 HTTP C2",
                # T1562 - Anti-analysis
                "IsDebuggerPresent":    "T1562.001 Anti-Debug",
                "CheckRemoteDebugger":  "T1562.001 Anti-Debug",
                "NtQueryInformationProcess": "T1562.001 Anti-Debug",
                # T1486 - Ransomware
                "MoveFileEx":           "T1486 Data Encryption/Ransomware",
            }

            mitre_hits = {}
            for func, count in call_counter.most_common(50):
                for api, technique in mitre_map.items():
                    if api.lower() in func.lower():
                        mitre_hits[technique] = mitre_hits.get(technique, [])
                        mitre_hits[technique].append(f"{func} (x{count})")

            out.append(f"\n  Top called functions:")
            for func, count in call_counter.most_common(15):
                out.append(f"    {func:<40} x{count}")

            if mitre_hits:
                out.append(f"\n  ⚠ MITRE ATT&CK Techniques detected:")
                for technique, apis in mitre_hits.items():
                    out.append(f"    [{technique}]")
                    for api in apis[:3]:
                        out.append(f"      → {api}")

    except Exception as e:
        out.append(f"  objdump error: {e}")

    # radare2 if available
    r2 = shutil.which("r2") or shutil.which("radare2")
    if r2:
        try:
            r = subprocess.run(
                [r2, "-q", "-c", "aaa; afl~?", str(path)],
                capture_output=True, text=True, timeout=30)
            if r.stdout.strip():
                out.append(f"\n  radare2 function count: {r.stdout.strip()}")
        except Exception:
            pass

    return "\n".join(out)


def tool_yara_generate(filepath):
    cprint(C_TOOL, f"  [YARA] Generating rule for {filepath}")
    path = Path(filepath)
    if not path.exists():
        return f"[YARA] File not found: {filepath}"
    try:
        data   = path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        md5    = hashlib.md5(data).hexdigest()
        ts     = datetime.now().strftime('%Y-%m-%d')

        # Extract candidate strings for YARA
        pattern     = re.compile(rb'[\x20-\x7e]{6,}')
        raw_strings = [s.decode('ascii') for s in pattern.findall(data)]

        # Score strings by uniqueness/interest
        interesting = []
        skip_kw = ['Windows','Microsoft','Program Files','System32',
                   'This program','DOS mode','GetProcAddress','LoadLibrary',
                   'kernel32','ntdll','user32','advapi32']
        for s in raw_strings:
            if len(s) < 6 or len(s) > 100:
                continue
            if any(kw.lower() in s.lower() for kw in skip_kw):
                continue
            # Prefer strings with unusual chars, IPs, domains, paths
            score = 0
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s): score += 5
            if re.search(r'https?://', s): score += 5
            if re.search(r'HKEY_|HKLM|HKCU', s): score += 4
            if re.search(r'C:\\', s): score += 3
            if re.search(r'\.exe|\.dll|\.bat|\.ps1', s): score += 3
            if re.search(r'[Pp]assword|[Ss]ecret|[Tt]oken|[Kk]ey', s): score += 4
            if re.search(r'[Mm]utex|[Cc]reate|[Ii]nject', s): score += 3
            if len(s) > 20: score += 2
            if score > 0:
                interesting.append((score, s))

        interesting.sort(key=lambda x: -x[0])
        top_strings = [s for _, s in interesting[:15]]

        # Extract unique byte sequences (4-byte sequences from entry point area)
        byte_patterns = []
        if is_pe(data) and len(data) > 0x3C + 4:
            pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
            if pe_offset + 6 < len(data):
                ep_rva = struct.unpack_from('<I', data, pe_offset + 40)[0]
                # Take 16 bytes from entry point area if accessible
                if ep_rva < len(data) and ep_rva + 16 < len(data):
                    ep_bytes = data[ep_rva:ep_rva+16]
                    byte_patterns.append(ep_bytes.hex())

        # Build rule name from filename
        rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', path.stem)
        if rule_name[0].isdigit():
            rule_name = "sample_" + rule_name

        # Generate YARA rule
        rule_lines = [
            f'rule {rule_name} {{',
            f'    meta:',
            f'        description = "Auto-generated by AGENTS-HQ Agent-06"',
            f'        author      = "Agent-06 RE Engine"',
            f'        date        = "{ts}"',
            f'        sha256      = "{sha256}"',
            f'        md5         = "{md5}"',
            f'        confidence  = "medium"',
            f'',
            f'    strings:',
        ]

        for i, s in enumerate(top_strings[:10]):
            escaped = s.replace('\\', '\\\\').replace('"', '\\"')
            rule_lines.append(f'        $str{i:02d} = "{escaped}" ascii wide nocase')

        if byte_patterns:
            for i, bp in enumerate(byte_patterns[:3]):
                hex_pairs = ' '.join(bp[j:j+2] for j in range(0, len(bp), 2))
                rule_lines.append(f'        $bytes{i:02d} = {{ {hex_pairs} }}')

        # Condition
        str_count = len(top_strings[:10])
        byte_count = len(byte_patterns[:3])
        if str_count + byte_count == 0:
            condition = "false  // No good strings found"
        elif str_count >= 5:
            threshold = max(2, str_count // 3)
            condition = f"{threshold} of ($str*)"
        elif byte_count > 0:
            condition = f"all of ($bytes*) and 1 of ($str*)"
        else:
            condition = f"any of them"

        rule_lines += [
            f'',
            f'    condition:',
            f'        {condition}',
            f'}}',
        ]

        rule = "\n".join(rule_lines)

        # Save YARA file
        YARA_DIR.mkdir(parents=True, exist_ok=True)
        yara_file = YARA_DIR / f"{sha256[:16]}_{path.stem}.yar"
        yara_file.write_text(rule)
        cprint(C_INFO, f"  [YARA] Saved: {yara_file}")

        # Validate with yara tool if available
        yara_bin = shutil.which("yara")
        validation = ""
        if yara_bin:
            try:
                r = subprocess.run([yara_bin, str(yara_file), str(path)],
                                   capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    validation = f"\n  Validation: ✓ Rule matches target file"
                    if r.stdout.strip():
                        validation += f" ({r.stdout.strip()})"
                else:
                    validation = f"\n  Validation error: {r.stderr[:200]}"
            except Exception:
                pass

        return (f"[YARA] Rule generated for {path.name}:\n"
                f"  Saved: {yara_file}\n"
                f"  Strings: {str_count} | Byte patterns: {byte_count}\n"
                f"{validation}\n\n{rule}")

    except Exception as e:
        return f"[YARA] Error: {e}"


def tool_rag_ingest(content):
    cprint(C_TOOL, "  [RAG] Ingesting to ChromaDB")
    try:
        import chromadb
        from chromadb.config import Settings as CS
        client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT,
                                     settings=CS(anonymized_telemetry=False))
        client.heartbeat()
        try:
            col = client.get_collection("security_docs")
        except Exception:
            col = client.create_collection("security_docs")
        ts    = datetime.now().strftime('%Y%m%d_%H%M')
        chunks, start = [], 0
        while start < len(content):
            chunks.append(content[start:start+800])
            start += 650
        ids  = [f"re_agent06_{ts}_{i}" for i in range(len(chunks))]
        meta = [{"source": "agent06_re", "type": "malware_analysis",
                 "date": ts} for _ in chunks]
        col.add(documents=chunks, metadatas=meta, ids=ids)
        cprint(C_INFO, f"  [RAG] {len(chunks)} chunks ingested")
        return f"[RAG] {len(chunks)} chunks ingested into security_docs collection"
    except ImportError:
        return "[RAG] chromadb not installed — skipping"
    except Exception as e:
        return f"[RAG] Error: {e}"


def tool_file_write(filepath, content, mode):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts   = datetime.now().strftime('%Y%m%d_%H%M')
    safe = re.sub(r'[^\w\-_\.]', '_', Path(filepath).name)
    filename = f"re_{mode}_{safe}_{ts}.md"
    fpath    = REPORTS_DIR / filename
    try:
        fpath.write_text(content, encoding='utf-8')
        cprint(C_TOOL, f"  [FILE] Saved: {fpath}")
        return f"[FILE_WRITE] Saved: {fpath}"
    except Exception as e:
        return f"[FILE_WRITE] Error: {e}"


# ── Tool Registry ─────────────────────────────────────────────
TOOLS = {
    "binary_info":      tool_binary_info,
    "hash_compute":     tool_hash_compute,
    "vt_check":         tool_vt_check,
    "pe_analysis":      tool_pe_analysis,
    "strings_extract":  tool_strings_extract,
    "ioc_extract":      tool_ioc_extract,
    "ghidra_decompile": tool_ghidra_decompile,
    "function_map":     tool_function_map,
    "yara_generate":    tool_yara_generate,
    "rag_ingest":       None,  # handled specially
    "file_write":       None,  # handled specially
}

def dispatch_tool(name, inp, target, mode):
    name = name.strip().lower()
    if name == "file_write":
        return tool_file_write(target, inp, mode)
    if name == "rag_ingest":
        return tool_rag_ingest(inp)
    if name not in TOOLS:
        return f"[ERROR] Unknown tool '{name}'. Available: {list(TOOLS.keys())}"
    return TOOLS[name](inp.strip())


# ── System Prompt ─────────────────────────────────────────────
def build_system_prompt(target, mode):
    wf     = MODE_WORKFLOWS.get(mode, MODE_WORKFLOWS["deep"])
    wf_str = "\n".join([f"  Step {i+1:02d} — {t}" for i, t in enumerate(wf)])

    mode_instructions = {
        "fast":   "FAST MODE: hash + strings + IOC extraction only. Skip PE/Ghidra. Move quickly.",
        "deep":   "DEEP MODE: Full pipeline. Use all tools. Correlate IOCs with VT findings.",
        "insane": ("INSANE MODE: Maximum depth. Run Ghidra twice if needed — "
                   "first pass all functions, second pass focused on suspicious functions. "
                   "Cross-reference all IOCs. Generate comprehensive threat dossier with "
                   "MITRE ATT&CK mapping, C2 infrastructure analysis, and persistence mechanisms."),
    }

    return f"""You are Agent-06, an autonomous malware reverse engineering agent operating in {mode.upper()} mode.
Target binary: {target}
Mode: {mode.upper()} — {MODE_LABELS.get(mode, mode)}

{mode_instructions.get(mode, '')}

AVAILABLE TOOLS (10 total):
  binary_info, hash_compute, vt_check, pe_analysis,
  strings_extract, ioc_extract, ghidra_decompile,
  function_map, yara_generate, rag_ingest, file_write

WORKFLOW FOR {mode.upper()} MODE:
{wf_str}

FORMAT FOR TOOL CALLS:
THOUGHT: <one sentence — what you are doing and why>
ACTION: <tool_name>
INPUT: <file path or content>

WHEN TASK IS COMPLETE:
THOUGHT: <brief summary>
FINAL_ANSWER: <complete RE report>

CRITICAL RULES:
1. ONE THOUGHT + ONE ACTION + ONE INPUT per response
2. Keep thinking to 3-4 sentences max
3. NEVER retry same tool with same input
4. INPUT for all file tools = the binary file path: {target}
5. INPUT for file_write = the FULL markdown RE report
6. INPUT for rag_ingest = summary of all findings
7. STOP after INPUT or FINAL_ANSWER line
8. Always include MITRE ATT&CK technique IDs when relevant
9. FINAL_ANSWER must include: hash, detections, IOCs, techniques, YARA rule location"""


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
                     "stop": ["\nOBSERVATION:", "[Wait", "[After"]},
    }
    try:
        r = requests.post(url, json=payload, stream=True, timeout=180)
        r.raise_for_status()
    except requests.exceptions.ConnectionError:
        cprint(C_WARN, f"[ERROR] Cannot reach ollama at {OLLAMA_HOST}:{OLLAMA_PORT}")
        sys.exit(1)

    full = ""
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
        return result

    t = re.search(r'THOUGHT:\s*(.*?)(?=ACTION:|FINAL_ANSWER:)', clean, re.DOTALL | re.IGNORECASE)
    a = re.search(r'ACTION:\s*(\w+)', clean, re.IGNORECASE)
    i = re.search(r'INPUT:\s*(.*?)(?=\nTHOUGHT:|\nACTION:|\nFINAL_ANSWER:|\nOBSERVATION:|$)',
                  clean, re.DOTALL | re.IGNORECASE)
    if t: result["thought"] = t.group(1).strip()
    if a: result["action"]  = a.group(1).strip()
    if i: result["input"]   = i.group(1).strip()
    return result


# ── ReAct Loop ────────────────────────────────────────────────
def react_loop(target, mode):
    mc = MODE_COLORS.get(mode, C_HEAD)
    cprint(mc, f"\n{'='*65}")
    cprint(mc, f"  AGENT-06 GHIDRA RE  |  {AGENT_MODEL}")
    cprint(mc, f"  Target : {target}")
    cprint(mc, f"  Mode   : {MODE_LABELS.get(mode, mode)}")
    cprint(mc, f"  Steps  : max {MODE_LIMITS.get(mode, 20)}")
    cprint(C_INFO, f"  VT Key : {'✓ active' if VIRUSTOTAL_KEY else '✗ missing'}")

    ghidra = find_ghidra()
    if ghidra:
        cprint(C_INFO, f"  Ghidra : {ghidra}")
    else:
        cprint(C_WARN, f"  Ghidra : NOT FOUND — decompile tool will fail")
        cprint(C_WARN, f"           Add to PATH or set GHIDRA_HOME")
    cprint(mc, f"{'='*65}\n")

    system   = build_system_prompt(target, mode)
    wf       = MODE_WORKFLOWS.get(mode, [])
    first_msg = (f"TARGET BINARY: {target}\nMODE: {mode}\n\n"
                 f"Begin reverse engineering. Execute step 1 now.{FORMAT_REMINDER}")

    messages       = [{"role": "system",    "content": system},
                      {"role": "user",      "content": first_msg}]
    final_answer   = None
    iteration      = 0
    action_history = []
    max_iter       = MODE_LIMITS.get(mode, 20)

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
            key = f"{parsed['action']}::{parsed['input'][:80]}"
            repeat_limit = 3 if mode == "insane" else 2
            if action_history.count(key) >= repeat_limit:
                cprint(C_WARN, f"  [LOOP] Repeated action — forcing next step")
                used   = set(h.split("::")[0] for h in action_history)
                unused = [x for x in wf if x not in used]
                messages.append({"role": "user", "content":
                    f"Repeated action detected. Move to next step.\n"
                    f"Remaining: {unused}{FORMAT_REMINDER}"})
                continue

            action_history.append(key)
            cprint(C_TOOL, f"\n  -> {parsed['action']}")
            observation = dispatch_tool(parsed["action"], parsed["input"], target, mode)
            preview     = observation[:1000] + ("..." if len(observation) > 1000 else "")
            cprint(C_OBS, f"\n  [OBSERVATION]\n{preview}")

            steps_done = set(h.split("::")[0] for h in action_history)
            next_hint  = ""
            for step in wf:
                if step not in steps_done:
                    next_hint = f"\nNEXT STEP: {step}"
                    break
            if not next_hint:
                next_hint = "\nAll steps done. Write FINAL_ANSWER with full RE dossier."

            messages.append({"role": "user", "content":
                f"OBSERVATION from {parsed['action']}:\n{observation}"
                f"{next_hint}{FORMAT_REMINDER}"})
        else:
            cprint(C_WARN, "  [PARSER] No action — nudging")
            messages.append({"role": "user", "content":
                f"Output action NOW:\n"
                f"THOUGHT: <one sentence>\nACTION: <tool>\nINPUT: {target}\n"
                f"Remaining: {[s for s in wf if s not in set(h.split('::')[0] for h in action_history)]}"})

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
                    self.wfile.write(b'{"status":"ok","agent":"06"}')
                except BrokenPipeError:
                    pass
            else:
                self.send_response(404)
                self.end_headers()
        def do_POST(self):
            if self.path == "/webhook/agent06":
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                try:
                    data   = json.loads(body)
                    target = data.get("file", data.get("target", ""))
                    mode   = data.get("mode", "deep")
                    if mode not in MODE_LIMITS:
                        mode = "deep"
                    if not target:
                        raise ValueError("Missing 'file' or 'target' field")
                    cprint(C_HEAD, f"\n[WEBHOOK] {target} mode:{mode}")
                    result = react_loop(target, mode)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "status": "complete", "result": result, "mode": mode}).encode())
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
    cprint(C_HEAD, f"  AGENT-06 RE — Webhook Server")
    cprint(C_HEAD, f"  Listening: 127.0.0.1:{N8N_WEBHOOK_PORT}")
    cprint(C_HEAD, f"  Endpoint: POST /webhook/agent06")
    cprint(C_HEAD, f'  Body: {{"file":"/path/to/binary","mode":"deep"}}')
    cprint(C_HEAD, f"  Modes: fast | deep | insane")
    cprint(C_HEAD, f"{'='*65}\n")
    HTTPServer(("127.0.0.1", N8N_WEBHOOK_PORT), Handler).serve_forever()


# ── Main ──────────────────────────────────────────────────────
def main():
    load_env()
    global VIRUSTOTAL_KEY
    VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

    parser = argparse.ArgumentParser(
        description="Agent-06 Ghidra RE — Autonomous malware analysis platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Modes:
  fast   — hash + strings + IOC extraction (no Ghidra)
  deep   — full pipeline including Ghidra decompilation
  insane — scorched earth, double Ghidra pass, full dossier

Examples:
  python3 agent_06_ghidra.py --target /path/to/binary --mode fast
  python3 agent_06_ghidra.py --target /path/to/malware.exe --mode deep
  python3 agent_06_ghidra.py --target /path/to/sample --mode insane
  python3 agent_06_ghidra.py --hash <sha256> --mode fast
  python3 agent_06_ghidra.py --n8n-server

Integration with Agent-10 (Dark Web):
  Agent-10 will POST samples via webhook:
  curl -X POST http://localhost:8766/webhook/agent06 \\
       -d '{"file":"/tmp/sample.bin","mode":"deep"}'

Output files:
  reports/re_<mode>_<sample>_<timestamp>.md   — Full RE report
  yara/<sha256_prefix>_<name>.yar             — YARA detection rule

.env keys (shared with agent_01_osint/.env):
  VIRUSTOTAL_API_KEY   virustotal.com
        """)
    parser.add_argument("--target", "-t", help="Binary file path to analyze")
    parser.add_argument("--hash",         help="SHA256 hash for VT lookup only")
    parser.add_argument("--mode",   "-m", default="deep",
                        choices=["fast", "deep", "insane"])
    parser.add_argument("--interactive", "-I", action="store_true")
    parser.add_argument("--n8n-server",        action="store_true")
    args = parser.parse_args()

    if args.n8n_server:
        run_webhook_server()
        return

    target = args.target
    mode   = args.mode

    if args.interactive:
        print(f"\n{C_HEAD}AGENT-06 Ghidra RE — Interactive Mode{C_RESET}")
        target = input("Binary path: ").strip()
        m = input("Mode [fast/deep/insane] (default: deep): ").strip().lower()
        if m in MODE_LIMITS:
            mode = m

    elif args.hash:
        # Hash-only mode — just VT check
        cprint(C_HEAD, f"\n[HASH LOOKUP] {args.hash}")
        result = tool_vt_check(args.hash)
        print(result)
        return

    elif not target:
        parser.print_help()
        sys.exit(0)

    if not Path(target).exists() and not args.hash:
        cprint(C_WARN, f"[ERROR] File not found: {target}")
        sys.exit(1)

    result = react_loop(target, mode)

    cprint(MODE_COLORS.get(mode, C_HEAD),
           f"\n{'='*65}\nRE REPORT [{mode.upper()}]:\n{'='*65}")
    print(result)


if __name__ == "__main__":
    main()
