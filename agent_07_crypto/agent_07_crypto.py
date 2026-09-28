#!/usr/bin/env python3
"""
AGENTS-HQ — Agent-07 Crypto Analysis v1

Three capability domains:
  1. HASH CRACKING     — identify algorithm, crack with hashcat (GPU) / john (CPU fallback)
  2. TLS AUDIT         — raw openssl cipher probing, protocol version detection,
                         known vuln checks (POODLE, BEAST, SWEET32, FREAK, DROWN)
  3. CERTIFICATE ANALYSIS — X.509 chain walk, key strength, validity, SANs, OCSP/CRL

Input routing:
  --target <domain|ip>              → TLS audit + cert chain
  --target hash:<value>             → hash identify → crack
  --target cert:<path>              → cert-only analysis
  --target binary:<path>            → entropy check → flag encrypted → notify Agent-06

Integration:
  Called by Agent-04 (crypto-specific targets), Agent-05 (red team crypto attacks),
  Agent-06 (encrypted binary found during RE).
  Pushes all findings into Agent-03 ChromaDB (security_docs).

Modes:
  fast   — TLS probe only / hash identify without cracking
  deep   — full pipeline: hash crack + TLS all-cipher sweep + full cert chain (default)
  audit  — TLS + cert only, no hash cracking

Usage:
  python3 agent_07_crypto.py --target example.com
  python3 agent_07_crypto.py --target example.com --mode audit
  python3 agent_07_crypto.py --target hash:5f4dcc3b5aa765d61d8327deb882cf99 --mode deep
  python3 agent_07_crypto.py --target cert:/path/to/cert.pem
  python3 agent_07_crypto.py --target binary:/path/to/file.bin
  python3 agent_07_crypto.py --wordlist /usr/share/wordlists/rockyou.txt --target hash:...
  python3 agent_07_crypto.py --interactive
  python3 agent_07_crypto.py --n8n-server
"""

import sys, json, subprocess, argparse, re, os, time, socket, math, struct
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

# ── Config ─────────────────────────────────────────────────────
OLLAMA_HOST      = "localhost"
OLLAMA_PORT      = 11434
AGENT_MODEL      = "qwen2.5:14b"
CHROMA_HOST      = "localhost"
CHROMA_PORT      = 8000
REPORTS_DIR      = Path(__file__).parent.parent / "reports"
N8N_WEBHOOK_PORT = int(os.environ.get("N8N_WEBHOOK_PORT", "8767"))
MAX_ITERATIONS   = 20
TIMEOUT_SSL      = 10    # per openssl s_client probe
TIMEOUT_CRACK    = 300   # hash cracking (5 min cap)
TIMEOUT_OPENSSL  = 15    # general openssl commands

DEFAULT_WORDLIST  = "/usr/share/wordlists/rockyou.txt"
TLS_CONNECT_PORT  = 443

# ── ANSI Colors ─────────────────────────────────────────────────
C_HEAD   = "\033[38;5;51m"    # cyan       — agent identity
C_PHASE  = "\033[38;5;39m"    # blue       — phase headers
C_TOOL   = "\033[38;5;226m"   # yellow     — tool calls
C_OBS    = "\033[38;5;82m"    # green      — observations
C_THINK  = "\033[38;5;244m"   # grey       — LLM thinking
C_ACT    = "\033[38;5;39m"    # blue       — LLM output
C_WARN   = "\033[38;5;196m"   # red        — warnings
C_CRIT   = "\033[38;5;201m"   # magenta    — critical findings
C_RESET  = "\033[0m"

def cprint(color, text, end="\n"):
    print(f"{color}{text}{C_RESET}", end=end, flush=True)

# ── Env / API keys ───────────────────────────────────────────────
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
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ══════════════════════════════════════════════════════════════
#  TOOL: HASH IDENTIFY
# ══════════════════════════════════════════════════════════════
HASH_PATTERNS = [
    # (regex, name, hashcat_mode, john_format)
    (r"^[0-9a-fA-F]{32}$",                    "MD5",           0,    "raw-md5"),
    (r"^[0-9a-fA-F]{40}$",                    "SHA1",          100,  "raw-sha1"),
    (r"^[0-9a-fA-F]{56}$",                    "SHA224",        1300, None),
    (r"^[0-9a-fA-F]{64}$",                    "SHA256",        1400, "raw-sha256"),
    (r"^[0-9a-fA-F]{96}$",                    "SHA384",        10800,None),
    (r"^[0-9a-fA-F]{128}$",                   "SHA512",        1700, "raw-sha512"),
    (r"^\$2[aby]\$\d{2}\$.{53}$",             "bcrypt",        3200, "bcrypt"),
    (r"^\$1\$.{1,8}\$.{22}$",                 "MD5-crypt",     500,  "md5crypt"),
    (r"^\$5\$.+\$.{43}$",                     "SHA256-crypt",  7400, "sha256crypt"),
    (r"^\$6\$.+\$.{86}$",                     "SHA512-crypt",  1800, "sha512crypt"),
    (r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$",   "NTLM+salt",     1000, "nt"),
    (r"^[0-9a-fA-F]{32}$",                    "NTLM",          1000, "nt"),
    (r"^[A-Za-z0-9+/]{24}={0,2}$",            "Base64 (check)",None, None),
    (r"^\$apr1\$.+\$.{22}$",                  "APR1-MD5",      1600, None),
    (r"^\$P\$.{31}$",                          "WP-phpass",     400,  "phpass"),
    (r"^\$H\$.{31}$",                          "phpass",        400,  "phpass"),
    (r"^[0-9a-fA-F]{16}$",                    "LM/Half-LM",    3000, "lm"),
    (r"^[A-F0-9]{32}:[A-F0-9]{32}$",          "NTLMv1",        1000, "nt"),
    (r"^\{SHA\}[A-Za-z0-9+/=]{28}$",          "LDAP-SHA1",     101,  None),
    (r"^\{SSHA\}[A-Za-z0-9+/=]{40}$",         "LDAP-SSHA1",    111,  None),
    (r"^[0-9a-fA-F]{32}:[a-zA-Z0-9]{16,}$",  "MD5+salt",      10,   None),
]

def tool_hash_identify(hash_value: str) -> str:
    cprint(C_TOOL, f"  [HASH_IDENTIFY] {hash_value[:64]}{'...' if len(hash_value)>64 else ''}")
    hash_value = hash_value.strip()
    matches = []
    for pattern, name, hc_mode, john_fmt in HASH_PATTERNS:
        if re.match(pattern, hash_value):
            matches.append({
                "algorithm": name,
                "hashcat_mode": hc_mode,
                "john_format": john_fmt,
            })
    if not matches:
        length = len(hash_value)
        return (f"[HASH_IDENTIFY] No pattern matched. Length={length}. "
                f"Could be custom, Argon2, or binary-encoded.")

    out = [f"[HASH_IDENTIFY] {len(matches)} candidate algorithm(s) for: {hash_value[:32]}..."]
    for m in matches:
        hc = f"hashcat mode {m['hashcat_mode']}" if m['hashcat_mode'] is not None else "no hashcat mode"
        jn = f"john --format={m['john_format']}" if m['john_format'] else "no john format"
        out.append(f"  • {m['algorithm']} — {hc} | {jn}")
    return "\n".join(out)


# ══════════════════════════════════════════════════════════════
#  TOOL: HASH CRACK
# ══════════════════════════════════════════════════════════════
def tool_hash_crack(hash_value: str, algorithm: str, wordlist: str) -> str:
    cprint(C_TOOL, f"  [HASH_CRACK] algo={algorithm} wordlist={wordlist}")

    if not Path(wordlist).exists():
        return (f"[HASH_CRACK] Wordlist not found: {wordlist}\n"
                f"  Try: /usr/share/wordlists/rockyou.txt or specify --wordlist")

    # Look up hashcat mode from algorithm name
    hc_mode = None
    john_fmt = None
    for _, name, hm, jf in HASH_PATTERNS:
        if algorithm.lower() in name.lower():
            hc_mode = hm
            john_fmt = jf
            break

    hash_file = Path("/tmp/agent07_hash.txt")
    hash_file.write_text(hash_value.strip() + "\n")

    # Try hashcat first
    hashcat_path = subprocess.run(["which", "hashcat"], capture_output=True, text=True).stdout.strip()
    if hashcat_path and hc_mode is not None:
        cprint(C_TOOL, f"  [HASH_CRACK] Using hashcat mode {hc_mode}")
        cmd = [
            "hashcat", "-m", str(hc_mode),
            str(hash_file), wordlist,
            "--potfile-disable", "--quiet", "--status-timer=30",
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_CRACK)
            output = r.stdout + r.stderr
            # hashcat outputs cracked hash as hash:plain
            for line in output.splitlines():
                if ":" in line and hash_value.lower() in line.lower():
                    plain = line.split(":")[-1].strip()
                    return f"[HASH_CRACK] ✅ CRACKED — Plaintext: {plain}"
            if "Exhausted" in output:
                return f"[HASH_CRACK] Wordlist exhausted. Hash not cracked."
            if output.strip():
                return f"[HASH_CRACK] hashcat output:\n{output[:2000]}"
            return "[HASH_CRACK] No result from hashcat."
        except subprocess.TimeoutExpired:
            return f"[HASH_CRACK] hashcat timed out after {TIMEOUT_CRACK}s."
        except Exception as e:
            cprint(C_WARN, f"  [HASH_CRACK] hashcat error: {e} — trying john")
    else:
        cprint(C_WARN, "  [HASH_CRACK] hashcat not found or mode unknown — falling back to john")

    # Fallback: john the ripper
    john_path = subprocess.run(["which", "john"], capture_output=True, text=True).stdout.strip()
    if not john_path:
        return "[HASH_CRACK] Neither hashcat nor john found. Install one to enable cracking."

    john_cmd = ["john", str(hash_file), f"--wordlist={wordlist}"]
    if john_fmt:
        john_cmd.append(f"--format={john_fmt}")
    try:
        subprocess.run(john_cmd, capture_output=True, text=True, timeout=TIMEOUT_CRACK)
        show = subprocess.run(["john", "--show", str(hash_file)],
                              capture_output=True, text=True, timeout=10)
        output = show.stdout.strip()
        if output and "0 password hashes cracked" not in output:
            return f"[HASH_CRACK] ✅ CRACKED (john):\n{output}"
        return "[HASH_CRACK] john: hash not cracked with provided wordlist."
    except subprocess.TimeoutExpired:
        return f"[HASH_CRACK] john timed out after {TIMEOUT_CRACK}s."
    except Exception as e:
        return f"[HASH_CRACK] john error: {e}"
    finally:
        hash_file.unlink(missing_ok=True)


# ══════════════════════════════════════════════════════════════
#  TLS HELPERS
# ══════════════════════════════════════════════════════════════

# All cipher suites to probe — grouped by protocol
TLS_PROBES = {
    "TLSv1.3": [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_128_CCM_SHA256",
        "TLS_AES_128_CCM_8_SHA256",
    ],
    "TLSv1.2": [
        "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-SHA384",      "ECDHE-RSA-AES128-SHA256",
        "ECDHE-RSA-AES256-SHA",         "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-RC4-SHA",
        "DHE-RSA-AES256-GCM-SHA384",    "DHE-RSA-AES128-GCM-SHA256",
        "DHE-RSA-AES256-SHA256",        "DHE-RSA-AES128-SHA256",
        "DHE-RSA-AES256-SHA",           "DHE-RSA-AES128-SHA",
        "AES256-GCM-SHA384",            "AES128-GCM-SHA256",
        "AES256-SHA256",                "AES128-SHA256",
        "AES256-SHA",                   "AES128-SHA",
        "RC4-SHA",                      "RC4-MD5",
        "DES-CBC3-SHA",
        "ECDHE-RSA-DES-CBC3-SHA",
        "DHE-RSA-DES-CBC3-SHA",
        "NULL-SHA256",                  "NULL-SHA",    "NULL-MD5",
        "ECDHE-RSA-NULL-SHA",
    ],
    "TLSv1.1": [
        "ECDHE-RSA-AES256-SHA", "ECDHE-RSA-AES128-SHA",
        "AES256-SHA",           "AES128-SHA",
        "DES-CBC3-SHA",         "RC4-SHA",    "RC4-MD5",
    ],
    "TLSv1": [
        "ECDHE-RSA-AES256-SHA", "ECDHE-RSA-AES128-SHA",
        "AES256-SHA",           "AES128-SHA",
        "DES-CBC3-SHA",         "RC4-SHA",    "RC4-MD5",
    ],
    "SSLv3": [
        "AES256-SHA", "AES128-SHA", "DES-CBC3-SHA", "RC4-SHA", "RC4-MD5",
    ],
}

WEAK_CIPHERS = {
    "RC4-SHA", "RC4-MD5", "ECDHE-RSA-RC4-SHA",
    "DES-CBC3-SHA", "ECDHE-RSA-DES-CBC3-SHA", "DHE-RSA-DES-CBC3-SHA",
    "NULL-SHA256", "NULL-SHA", "NULL-MD5", "ECDHE-RSA-NULL-SHA",
    "EXPORT", "EXP",
}

WEAK_PROTOCOLS = {"SSLv3", "TLSv1", "TLSv1.1"}

def _probe_cipher(host: str, port: int, proto: str, cipher: str) -> bool:
    """Return True if the server accepts this proto+cipher combo."""
    proto_flag = {
        "SSLv3":  "-ssl3",
        "TLSv1":  "-tls1",
        "TLSv1.1":"-tls1_1",
        "TLSv1.2":"-tls1_2",
        "TLSv1.3":"-tls1_3",
    }.get(proto, "-tls1_2")

    cmd = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        proto_flag,
        "-cipher", cipher,
        "-no_ticket", "-brief",
    ]
    # TLS 1.3 uses -ciphersuites not -cipher
    if proto == "TLSv1.3":
        cmd = [
            "openssl", "s_client",
            "-connect", f"{host}:{port}",
            proto_flag,
            "-ciphersuites", cipher,
            "-no_ticket", "-brief",
        ]

    try:
        r = subprocess.run(
            cmd,
            input="Q\n", capture_output=True, text=True,
            timeout=TIMEOUT_SSL,
        )
        combined = r.stdout + r.stderr
        return "Cipher is " in combined or "CONNECTION ESTABLISHED" in combined
    except Exception:
        return False


def tool_tls_audit(host: str, port: int = TLS_CONNECT_PORT, fast: bool = False) -> str:
    cprint(C_TOOL, f"  [TLS_AUDIT] {host}:{port} {'(fast)' if fast else '(full sweep)'}")

    supported: dict[str, list[str]] = {}
    weak_found: list[str] = []
    weak_proto_found: list[str] = []

    probes = {"TLSv1.2": TLS_PROBES["TLSv1.2"], "TLSv1.3": TLS_PROBES["TLSv1.3"]} \
             if fast else TLS_PROBES

    total = sum(len(v) for v in probes.values())
    done = 0

    for proto, ciphers in probes.items():
        for cipher in ciphers:
            if _probe_cipher(host, port, proto, cipher):
                supported.setdefault(proto, []).append(cipher)
                if proto in WEAK_PROTOCOLS:
                    if proto not in weak_proto_found:
                        weak_proto_found.append(proto)
                if any(w in cipher for w in WEAK_CIPHERS):
                    weak_found.append(f"{proto}/{cipher}")
            done += 1
            if done % 10 == 0:
                cprint(C_THINK, f"  [TLS_AUDIT] probed {done}/{total}...", end="\r")

    # Summarise
    lines = [f"\n[TLS_AUDIT] Results for {host}:{port}"]
    lines.append("=" * 60)

    if not any(supported.values()):
        lines.append("  No TLS connections succeeded. Port closed or not TLS?")
        return "\n".join(lines)

    for proto, ciphers in supported.items():
        proto_label = f"⚠ {proto} (WEAK)" if proto in WEAK_PROTOCOLS else proto
        lines.append(f"\n  {proto_label}: {len(ciphers)} cipher(s) accepted")
        for c in ciphers:
            marker = " ⚠ WEAK" if any(w in c for w in WEAK_CIPHERS) else ""
            lines.append(f"    • {c}{marker}")

    lines.append("\n--- Vulnerability Checks ---")

    # POODLE: SSLv3 accepted
    if "SSLv3" in supported and supported["SSLv3"]:
        lines.append("  ⚠ POODLE (CVE-2014-3566) — SSLv3 is ENABLED")
    else:
        lines.append("  ✓ POODLE — SSLv3 disabled")

    # BEAST: TLS 1.0 + CBC cipher
    tls10_ciphers = supported.get("TLSv1", [])
    cbc_in_tls10 = [c for c in tls10_ciphers if "SHA" in c and "GCM" not in c and "RC4" not in c]
    if cbc_in_tls10:
        lines.append("  ⚠ BEAST (CVE-2011-3389) — TLS 1.0 + CBC cipher in use")
    else:
        lines.append("  ✓ BEAST — TLS 1.0 CBC not exposed")

    # SWEET32: 3DES present
    triple_des = [f"{p}/{c}" for p, cs in supported.items()
                  for c in cs if "DES-CBC3" in c or "3DES" in c]
    if triple_des:
        lines.append(f"  ⚠ SWEET32 (CVE-2016-2183) — 3DES cipher(s): {', '.join(triple_des[:3])}")
    else:
        lines.append("  ✓ SWEET32 — 3DES not accepted")

    # FREAK: EXPORT cipher
    export_ciphers = [f"{p}/{c}" for p, cs in supported.items()
                      for c in cs if "EXPORT" in c or "EXP-" in c]
    if export_ciphers:
        lines.append(f"  ⚠ FREAK (CVE-2015-0204) — EXPORT cipher(s): {', '.join(export_ciphers)}")
    else:
        lines.append("  ✓ FREAK — EXPORT ciphers not accepted")

    # NULL cipher
    null_ciphers = [f"{p}/{c}" for p, cs in supported.items()
                    for c in cs if "NULL" in c]
    if null_ciphers:
        lines.append(f"  ⚠ NULL AUTH — No encryption: {', '.join(null_ciphers)}")
    else:
        lines.append("  ✓ NULL — No null-encryption ciphers")

    # RC4
    rc4_ciphers = [f"{p}/{c}" for p, cs in supported.items()
                   for c in cs if "RC4" in c]
    if rc4_ciphers:
        lines.append(f"  ⚠ RC4 BIAS (CVE-2015-2808) — RC4 accepted: {', '.join(rc4_ciphers[:3])}")
    else:
        lines.append("  ✓ RC4 — Not accepted")

    if weak_proto_found:
        lines.append(f"\n  ⚠ Weak protocol(s) enabled: {', '.join(weak_proto_found)}")
    if weak_found:
        lines.append(f"  ⚠ Weak cipher(s): {', '.join(weak_found[:6])}")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════
#  TOOL: CERT FETCH + ANALYZE
# ══════════════════════════════════════════════════════════════
def _openssl(args: list[str], stdin_data: str = "") -> tuple[str, str]:
    try:
        r = subprocess.run(
            ["openssl"] + args,
            input=stdin_data, capture_output=True, text=True,
            timeout=TIMEOUT_OPENSSL,
        )
        return r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return "", "[openssl timeout]"
    except FileNotFoundError:
        return "", "[openssl not found]"


def tool_cert_fetch(host: str, port: int = TLS_CONNECT_PORT) -> str:
    """Fetch PEM certificate from live host via openssl s_client."""
    cprint(C_TOOL, f"  [CERT_FETCH] {host}:{port}")
    stdout, stderr = _openssl(
        ["s_client", "-connect", f"{host}:{port}",
         "-servername", host, "-showcerts", "-no_ticket"],
        stdin_data="Q\n",
    )
    combined = stdout + stderr
    if "-----BEGIN CERTIFICATE-----" not in combined:
        return f"[CERT_FETCH] No certificate returned.\n{stderr[:500]}"

    # Extract first cert (leaf)
    pem_blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        combined, re.DOTALL
    )
    if not pem_blocks:
        return "[CERT_FETCH] Could not parse certificate PEM."

    # Write leaf cert to temp file for further analysis
    leaf_path = Path("/tmp/agent07_leaf.pem")
    leaf_path.write_text(pem_blocks[0])

    chain_path = Path("/tmp/agent07_chain.pem")
    chain_path.write_text("\n".join(pem_blocks))

    return f"[CERT_FETCH] Retrieved {len(pem_blocks)} certificate(s). Saved for analysis."


def _parse_cert(pem_path: str) -> dict:
    """Parse a PEM cert into a dict of fields via openssl x509."""
    out = {}
    stdout, _ = _openssl(["x509", "-in", pem_path, "-noout",
                           "-subject", "-issuer", "-dates",
                           "-fingerprint", "-sha256",
                           "-serial", "-ext", "subjectAltName",
                           "-pubkey"])
    for line in stdout.splitlines():
        if line.startswith("subject="):
            out["subject"] = line[8:].strip()
        elif line.startswith("issuer="):
            out["issuer"] = line[7:].strip()
        elif line.startswith("notBefore="):
            out["not_before"] = line[10:].strip()
        elif line.startswith("notAfter="):
            out["not_after"] = line[9:].strip()
        elif "Fingerprint=" in line:
            out["sha256_fingerprint"] = line.strip()
        elif line.startswith("serial="):
            out["serial"] = line[7:].strip()
        elif "DNS:" in line or "IP Address:" in line:
            sans = re.findall(r"(DNS:[^\s,]+|IP Address:[^\s,]+)", line)
            out["san"] = ", ".join(sans)

    # Key strength
    pubkey_out, _ = _openssl(["x509", "-in", pem_path, "-noout", "-text"])
    key_match = re.search(r"Public-Key: \((\d+) bit\)", pubkey_out)
    sig_match  = re.search(r"Signature Algorithm: (\S+)", pubkey_out)
    key_type   = re.search(r"(rsaEncryption|id-ecPublicKey|dsaEncryption)", pubkey_out)
    out["key_bits"]     = key_match.group(1) if key_match else "unknown"
    out["key_type"]     = key_type.group(1) if key_type else "unknown"
    out["sig_algorithm"]= sig_match.group(1) if sig_match else "unknown"

    return out


def tool_cert_analyze(cert_path: str) -> str:
    cprint(C_TOOL, f"  [CERT_ANALYZE] {cert_path}")
    if not Path(cert_path).exists():
        return f"[CERT_ANALYZE] File not found: {cert_path}"

    info = _parse_cert(cert_path)
    now  = datetime.now(timezone.utc)

    lines = [f"\n[CERT_ANALYZE] {cert_path}", "=" * 60]
    lines.append(f"  Subject         : {info.get('subject', 'n/a')}")
    lines.append(f"  Issuer          : {info.get('issuer', 'n/a')}")
    lines.append(f"  Not Before      : {info.get('not_before', 'n/a')}")
    lines.append(f"  Not After       : {info.get('not_after', 'n/a')}")
    lines.append(f"  SAN             : {info.get('san', 'none')}")
    lines.append(f"  Serial          : {info.get('serial', 'n/a')}")
    lines.append(f"  SHA256 FP       : {info.get('sha256_fingerprint', 'n/a')}")
    lines.append(f"  Key Type        : {info.get('key_type', 'n/a')}")
    lines.append(f"  Key Bits        : {info.get('key_bits', 'n/a')}")
    lines.append(f"  Sig Algorithm   : {info.get('sig_algorithm', 'n/a')}")

    # Expiry check
    not_after_str = info.get("not_after", "")
    try:
        exp = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        delta = exp - now
        if delta.days < 0:
            lines.append(f"\n  ⚠ EXPIRED {abs(delta.days)} days ago")
        elif delta.days < 30:
            lines.append(f"\n  ⚠ Expires in {delta.days} days (SOON)")
        else:
            lines.append(f"\n  ✓ Valid for {delta.days} more days")
    except Exception:
        lines.append("\n  [!] Could not parse expiry date")

    # Self-signed check
    subj = info.get("subject", "")
    issuer = info.get("issuer", "")
    if subj and issuer and subj.strip() == issuer.strip():
        lines.append("  ⚠ SELF-SIGNED certificate")
    else:
        lines.append("  ✓ Not self-signed")

    # Key strength warnings
    try:
        bits = int(info.get("key_bits", 0))
        key_type = info.get("key_type", "")
        if "rsa" in key_type.lower() and bits < 2048:
            lines.append(f"  ⚠ WEAK RSA key: {bits} bits (minimum 2048)")
        elif "rsa" in key_type.lower() and bits < 4096:
            lines.append(f"  ~ RSA {bits}-bit (acceptable, 4096 recommended)")
        elif "rsa" in key_type.lower():
            lines.append(f"  ✓ RSA {bits}-bit (strong)")
    except ValueError:
        pass

    # Signature algorithm warnings
    sig_alg = info.get("sig_algorithm", "")
    if "md5" in sig_alg.lower():
        lines.append("  ⚠ MD5 signature algorithm — cryptographically broken")
    elif "sha1" in sig_alg.lower():
        lines.append("  ⚠ SHA1 signature algorithm — deprecated, consider SHA256+")
    else:
        lines.append(f"  ✓ Signature algorithm: {sig_alg}")

    return "\n".join(lines)


def tool_cert_chain(host: str, port: int = TLS_CONNECT_PORT) -> str:
    """Walk full cert chain, analyze each cert."""
    cprint(C_TOOL, f"  [CERT_CHAIN] {host}:{port}")

    fetch_result = tool_cert_fetch(host, port)
    if "No certificate" in fetch_result or "not found" in fetch_result.lower():
        return fetch_result

    chain_path = Path("/tmp/agent07_chain.pem")
    if not chain_path.exists():
        return "[CERT_CHAIN] Chain PEM not found. Run cert_fetch first."

    # Split chain into individual certs
    chain_pem = chain_path.read_text()
    certs = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        chain_pem, re.DOTALL
    )

    lines = [f"\n[CERT_CHAIN] {host}:{port} — {len(certs)} certificate(s) in chain"]
    lines.append("=" * 60)

    for i, pem in enumerate(certs):
        label = {0: "LEAF", len(certs)-1: "ROOT CA"}.get(i, f"INTERMEDIATE-{i}")
        tmp = Path(f"/tmp/agent07_cert_{i}.pem")
        tmp.write_text(pem)
        analysis = tool_cert_analyze(str(tmp))
        lines.append(f"\n[{label}]{analysis}")
        tmp.unlink(missing_ok=True)

    # Verify chain integrity
    if len(certs) > 1:
        verify_out, verify_err = _openssl(
            ["verify", "-CAfile", "/tmp/agent07_chain.pem",
             "/tmp/agent07_leaf.pem"]
        )
        if "OK" in verify_out:
            lines.append("\n  ✓ Chain verification: OK")
        else:
            lines.append(f"\n  ⚠ Chain verification issue: {verify_err.strip()[:200]}")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════
#  TOOL: ENTROPY CHECK (encrypted / compressed binary detection)
# ══════════════════════════════════════════════════════════════
def tool_entropy_check(file_path: str) -> str:
    cprint(C_TOOL, f"  [ENTROPY_CHECK] {file_path}")
    p = Path(file_path)
    if not p.exists():
        return f"[ENTROPY_CHECK] File not found: {file_path}"

    data = p.read_bytes()
    if len(data) == 0:
        return "[ENTROPY_CHECK] File is empty."

    # Shannon entropy
    counts = Counter(data)
    total  = len(data)
    entropy = -sum((c/total) * math.log2(c/total) for c in counts.values() if c > 0)

    size_kb = total / 1024
    unique_bytes = len(counts)

    lines = [f"\n[ENTROPY_CHECK] {p.name}"]
    lines.append(f"  Size            : {size_kb:.1f} KB ({total} bytes)")
    lines.append(f"  Unique bytes    : {unique_bytes}/256")
    lines.append(f"  Shannon entropy : {entropy:.4f} bits/byte")
    lines.append("")

    if entropy >= 7.5:
        lines.append("  ⚠ HIGH ENTROPY (≥7.5) — likely encrypted or compressed")
        lines.append("    Interpretation: random-looking data, cryptographic or packed")
        lines.append("    Recommend: forward to Agent-06 for RE + packer detection")
    elif entropy >= 6.5:
        lines.append("  ~ MODERATE-HIGH ENTROPY (6.5–7.5) — possibly compressed")
        lines.append("    Interpretation: could be ZIP/gzip/zlib payload")
    elif entropy >= 4.0:
        lines.append("  ✓ NORMAL ENTROPY (4.0–6.5) — typical binary or text")
    else:
        lines.append("  ~ LOW ENTROPY (<4.0) — highly structured data or mostly zeros")

    # Magic bytes check
    magic = data[:4]
    if magic[:2] == b"MZ":
        lines.append("  • Magic: PE/DOS executable (MZ header)")
    elif magic == b"\x7fELF":
        lines.append("  • Magic: ELF executable")
    elif magic[:4] == b"PK\x03\x04":
        lines.append("  • Magic: ZIP archive")
    elif magic[:3] in (b"\x1f\x8b\x08", ):
        lines.append("  • Magic: gzip compressed")
    elif magic[:4] == b"\xfd7zXZ":
        lines.append("  • Magic: XZ compressed")
    elif magic[:4] == b"Rar!":
        lines.append("  • Magic: RAR archive")
    elif magic[:4] == b"\xcf\xfa\xed\xfe" or magic[:4] == b"\xce\xfa\xed\xfe":
        lines.append("  • Magic: Mach-O binary")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════
#  TOOL: OPENSSL RAW
# ══════════════════════════════════════════════════════════════
def tool_openssl_run(args_string: str) -> str:
    """Run an arbitrary openssl command (args as a space-separated string)."""
    cprint(C_TOOL, f"  [OPENSSL] openssl {args_string[:80]}")
    args = args_string.strip().split()
    # Safety: block write operations
    dangerous = ["-out", "genrsa", "req", "ca", "pkcs12"]
    for d in dangerous:
        if d in args:
            return f"[OPENSSL] Blocked: '{d}' not permitted (read-only mode)."
    stdout, stderr = _openssl(args)
    out = stdout + stderr
    if not out.strip():
        return "[OPENSSL] No output."
    return out[:3000] + ("\n...[truncated]" if len(out) > 3000 else "")


# ══════════════════════════════════════════════════════════════
#  TOOL: RAG LOOKUP / INGEST
# ══════════════════════════════════════════════════════════════
def tool_rag_lookup(query: str) -> str:
    cprint(C_TOOL, f"  [RAG_LOOKUP] {query[:60]}")
    try:
        import urllib.request
        payload = json.dumps({"query_texts": [query], "n_results": 5,
                              "where": None}).encode()
        req = urllib.request.Request(
            f"http://{CHROMA_HOST}:{CHROMA_PORT}/api/v1/collections/security_docs/query",
            data=payload, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        docs = data.get("documents", [[]])[0]
        if not docs:
            return "[RAG_LOOKUP] No relevant documents found."
        return "[RAG_LOOKUP] Relevant knowledge:\n" + "\n---\n".join(docs[:3])
    except Exception as e:
        return f"[RAG_LOOKUP] Error: {e}"


def tool_rag_ingest(text: str, doc_id: str = None) -> str:
    cprint(C_TOOL, f"  [RAG_INGEST] {len(text)} chars")
    try:
        import urllib.request, uuid
        doc_id = doc_id or f"agent07_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        payload = json.dumps({
            "ids": [doc_id],
            "documents": [text],
            "metadatas": [{"source": "agent07_crypto", "ts": datetime.utcnow().isoformat()}]
        }).encode()
        req = urllib.request.Request(
            f"http://{CHROMA_HOST}:{CHROMA_PORT}/api/v1/collections/security_docs/upsert",
            data=payload, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
        return f"[RAG_INGEST] Stored as {doc_id}"
    except Exception as e:
        return f"[RAG_INGEST] Error: {e}"


# ══════════════════════════════════════════════════════════════
#  TOOL: FILE WRITE
# ══════════════════════════════════════════════════════════════
def tool_file_write(filename: str, content: str) -> str:
    cprint(C_TOOL, f"  [FILE_WRITE] {filename}")
    out_path = REPORTS_DIR / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content)
    return f"[FILE_WRITE] Written: {out_path}"


# ══════════════════════════════════════════════════════════════
#  TOOL DISPATCHER
# ══════════════════════════════════════════════════════════════
TOOL_SCHEMA = [
    {
        "name": "hash_identify",
        "description": "Identify the algorithm of an unknown hash value.",
        "parameters": {
            "hash_value": "The hash string to identify."
        }
    },
    {
        "name": "hash_crack",
        "description": "Attempt to crack a hash using hashcat (GPU) or john (CPU fallback) with a wordlist.",
        "parameters": {
            "hash_value": "The hash to crack.",
            "algorithm":  "Algorithm name from hash_identify (e.g. MD5, SHA1, bcrypt).",
            "wordlist":   "Absolute path to wordlist file. Default: /usr/share/wordlists/rockyou.txt"
        }
    },
    {
        "name": "tls_audit",
        "description": "Enumerate supported TLS cipher suites and protocol versions on a host, then check for POODLE/BEAST/SWEET32/FREAK/RC4/NULL vulnerabilities.",
        "parameters": {
            "host": "Target hostname or IP.",
            "port": "Port number (default 443).",
            "fast": "true = TLS1.2/1.3 only; false = full sweep including SSLv3/TLS1.0/1.1"
        }
    },
    {
        "name": "cert_fetch",
        "description": "Fetch the TLS certificate chain from a live host and save for analysis.",
        "parameters": {
            "host": "Target hostname or IP.",
            "port": "Port (default 443)."
        }
    },
    {
        "name": "cert_analyze",
        "description": "Parse and audit a PEM certificate file: validity, key strength, signature algorithm, SANs, expiry, self-signed check.",
        "parameters": {
            "cert_path": "Path to PEM certificate file."
        }
    },
    {
        "name": "cert_chain",
        "description": "Fetch and analyze the full certificate chain from a live host, including intermediate and root CA certs.",
        "parameters": {
            "host": "Target hostname or IP.",
            "port": "Port (default 443)."
        }
    },
    {
        "name": "entropy_check",
        "description": "Compute Shannon entropy of a file to detect encryption or compression. High entropy (≥7.5) indicates likely encrypted/packed content.",
        "parameters": {
            "file_path": "Absolute path to the file to analyze."
        }
    },
    {
        "name": "openssl_run",
        "description": "Run a raw openssl command for advanced analysis (read-only operations only).",
        "parameters": {
            "args_string": "openssl arguments as a space-separated string (e.g. 'x509 -in cert.pem -noout -text')."
        }
    },
    {
        "name": "rag_lookup",
        "description": "Search the ChromaDB knowledge base for crypto-related CVEs, advisories, or prior findings.",
        "parameters": {
            "query": "Search query string."
        }
    },
    {
        "name": "rag_ingest",
        "description": "Store analysis findings into ChromaDB for other agents to access.",
        "parameters": {
            "text":   "Content to store.",
            "doc_id": "Optional document ID."
        }
    },
    {
        "name": "file_write",
        "description": "Write a report or output to the reports/ directory.",
        "parameters": {
            "filename": "Filename (e.g. CRYPTO_example_com_20250101.md).",
            "content":  "Full file content."
        }
    },
]


def dispatch_tool(name: str, params: dict, wordlist: str = DEFAULT_WORDLIST) -> str:
    if name == "hash_identify":
        return tool_hash_identify(params.get("hash_value", ""))
    elif name == "hash_crack":
        return tool_hash_crack(
            params.get("hash_value", ""),
            params.get("algorithm", ""),
            params.get("wordlist", wordlist),
        )
    elif name == "tls_audit":
        return tool_tls_audit(
            params.get("host", ""),
            int(params.get("port", TLS_CONNECT_PORT)),
            str(params.get("fast", "false")).lower() == "true",
        )
    elif name == "cert_fetch":
        return tool_cert_fetch(
            params.get("host", ""),
            int(params.get("port", TLS_CONNECT_PORT)),
        )
    elif name == "cert_analyze":
        return tool_cert_analyze(params.get("cert_path", ""))
    elif name == "cert_chain":
        return tool_cert_chain(
            params.get("host", ""),
            int(params.get("port", TLS_CONNECT_PORT)),
        )
    elif name == "entropy_check":
        return tool_entropy_check(params.get("file_path", ""))
    elif name == "openssl_run":
        return tool_openssl_run(params.get("args_string", ""))
    elif name == "rag_lookup":
        return tool_rag_lookup(params.get("query", ""))
    elif name == "rag_ingest":
        return tool_rag_ingest(params.get("text", ""), params.get("doc_id"))
    elif name == "file_write":
        return tool_file_write(params.get("filename", "output.md"), params.get("content", ""))
    else:
        return f"[DISPATCH] Unknown tool: {name}"


# ══════════════════════════════════════════════════════════════
#  OLLAMA CALL
# ══════════════════════════════════════════════════════════════
def ollama_call(messages: list[dict], stream: bool = True) -> str:
    import urllib.request
    payload = json.dumps({
        "model":    AGENT_MODEL,
        "messages": messages,
        "stream":   stream,
    }).encode()
    req = urllib.request.Request(
        f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/chat",
        data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    full_text = ""
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            for raw_line in resp:
                line = raw_line.decode().strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    token = obj.get("message", {}).get("content", "")
                    full_text += token
                    if stream:
                        print(token, end="", flush=True)
                except json.JSONDecodeError:
                    pass
    except Exception as e:
        return f"[OLLAMA] Error: {e}"
    if stream:
        print()
    return full_text


# ══════════════════════════════════════════════════════════════
#  REACT LOOP
# ══════════════════════════════════════════════════════════════
def build_system_prompt(mode: str, target: str, wordlist: str) -> str:
    tool_docs = "\n".join(
        f"  {t['name']}({', '.join(t['parameters'].keys())}) — {t['description']}"
        for t in TOOL_SCHEMA
    )
    return f"""You are Agent-07 — the cryptography analysis specialist in the AGENTS-HQ security intelligence platform.

MODE: {mode.upper()}
TARGET: {target}
WORDLIST: {wordlist}

Your mission: perform deep cryptographic analysis of the target.

Available tools:
{tool_docs}

Mode behaviour:
  fast  — TLS probe (TLS1.2/1.3 only) + hash identify (no cracking)
  deep  — Full TLS cipher sweep (SSLv3 through TLS1.3) + hash crack + full cert chain
  audit — TLS audit + cert chain only (no hash cracking)

Input routing you must follow:
  • Target starts with "hash:"   → hash_identify first, then hash_crack if mode=deep
  • Target starts with "cert:"   → cert_analyze only (local file path)
  • Target starts with "binary:" → entropy_check only (flag encrypted if >7.5)
  • Target is domain/IP          → tls_audit + cert_chain
  • Ambiguous                    → rag_lookup first for context, then decide

ReAct format — you MUST follow this exactly:
  THOUGHT: <your reasoning about what to do next>
  ACTION: <tool_name>
  PARAMS: <JSON object with parameters>

After receiving OBSERVATION, continue with next THOUGHT/ACTION or conclude:
  FINAL: <your complete findings summary>

Rules:
  1. Always start with rag_lookup for any CVE or known-vuln context.
  2. For hash targets: hash_identify FIRST, then crack (deep mode only).
  3. For domain/IP: cert_chain covers cert_fetch + cert_analyze in one call.
  4. Always rag_ingest your final findings summary.
  5. Always file_write the full report at the end.
  6. If entropy_check returns ≥7.5, note "RECOMMEND: forward to Agent-06 for RE" in FINAL.
  7. Report filename format: CRYPTO_<target_sanitized>_<YYYYMMDD_HHMMSS>.md
  8. Do not repeat a tool with identical parameters (loop guard).
  9. Emit FINAL when findings are complete or max iterations approach.
"""


def parse_action(text: str) -> tuple[str | None, dict | None]:
    """Extract ACTION and PARAMS from LLM output."""
    action_match = re.search(r"ACTION:\s*(\w+)", text, re.IGNORECASE)
    params_match  = re.search(r"PARAMS:\s*(\{.*?\})", text, re.DOTALL | re.IGNORECASE)

    if not action_match:
        return None, None

    tool_name = action_match.group(1).strip()
    params = {}
    if params_match:
        try:
            params = json.loads(params_match.group(1))
        except json.JSONDecodeError:
            # Try to extract key:value pairs manually
            raw = params_match.group(1)
            for m in re.finditer(r'"(\w+)"\s*:\s*"([^"]*)"', raw):
                params[m.group(1)] = m.group(2)

    return tool_name, params


def react_loop(target: str, mode: str, wordlist: str) -> str:
    cprint(C_HEAD, f"\n{'='*64}")
    cprint(C_HEAD, f"  AGENT-07 — CRYPTO ANALYSIS")
    cprint(C_HEAD, f"  Target : {target}")
    cprint(C_HEAD, f"  Mode   : {mode.upper()}")
    cprint(C_HEAD, f"{'='*64}\n")

    system_prompt = build_system_prompt(mode, target, wordlist)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": f"Begin crypto analysis of target: {target}\nMode: {mode}"},
    ]

    iteration     = 0
    action_history: list[str] = []
    final_output  = ""

    while iteration < MAX_ITERATIONS:
        iteration += 1
        cprint(C_PHASE, f"\n── Iteration {iteration}/{MAX_ITERATIONS} ──────────────────")
        cprint(C_THINK, "  [LLM] Thinking...")

        response = ollama_call(messages, stream=True)
        messages.append({"role": "assistant", "content": response})

        # Check for FINAL
        if "FINAL:" in response:
            final_match = re.search(r"FINAL:\s*(.*)", response, re.DOTALL)
            if final_match:
                final_output = final_match.group(1).strip()
            cprint(C_OBS, "\n[✓] Agent concluded.")
            break

        tool_name, params = parse_action(response)
        if not tool_name:
            cprint(C_WARN, "  [!] No ACTION found in response. Prompting agent...")
            messages.append({
                "role": "user",
                "content": "No ACTION detected. Continue with next THOUGHT/ACTION/PARAMS or emit FINAL."
            })
            continue

        # Loop guard
        action_key = f"{tool_name}:{json.dumps(params, sort_keys=True)}"
        if action_history.count(action_key) >= 2:
            observation = f"[LOOP_GUARD] Tool '{tool_name}' with same params already called twice. Choose a different action or emit FINAL."
        else:
            action_history.append(action_key)
            cprint(C_TOOL, f"\n  → Calling: {tool_name}({params})")
            observation = dispatch_tool(tool_name, params, wordlist)

        cprint(C_OBS, f"\n  [OBS] {observation[:500]}{'...' if len(observation) > 500 else ''}")
        messages.append({"role": "user", "content": f"OBSERVATION: {observation}"})

    else:
        cprint(C_WARN, f"\n[!] Max iterations ({MAX_ITERATIONS}) reached.")
        final_output = "[Agent-07] Max iterations reached. Partial findings above."

    return final_output or "Analysis complete. See report in reports/ directory."


# ══════════════════════════════════════════════════════════════
#  INTERACTIVE MODE
# ══════════════════════════════════════════════════════════════
def interactive_mode():
    cprint(C_HEAD, "\n═══════════════════════════════════════════")
    cprint(C_HEAD, "  AGENT-07 — CRYPTO ANALYSIS  [interactive]")
    cprint(C_HEAD, "═══════════════════════════════════════════")
    print("  Type 'exit' to quit.\n")

    while True:
        try:
            target = input(f"{C_PHASE}  Target > {C_RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break
        if not target or target.lower() in ("exit", "quit"):
            break

        mode = input(f"{C_PHASE}  Mode [fast/deep/audit] (default: deep) > {C_RESET}").strip() or "deep"
        wordlist = input(f"{C_PHASE}  Wordlist (Enter = {DEFAULT_WORDLIST}) > {C_RESET}").strip() or DEFAULT_WORDLIST

        react_loop(target, mode, wordlist)


# ══════════════════════════════════════════════════════════════
#  N8N WEBHOOK SERVER  (TLS + cert analysis only — no hash cracking)
# ══════════════════════════════════════════════════════════════
def start_webhook_server():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == "/health":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                try:
                    self.wfile.write(b'{"status":"ok","agent":"07"}')
                except BrokenPipeError:
                    pass
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            if self.path != "/webhook/agent07":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)
            try:
                data   = json.loads(body)
                target = data.get("target", "").strip()
                mode   = data.get("mode", "audit")
            except Exception:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error":"invalid JSON"}')
                return

            if not target:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error":"target required"}')
                return

            # Hash cracking not allowed via webhook (needs local wordlists + TTY)
            if target.startswith("hash:"):
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error":"hash cracking not available via webhook - use CLI"}')
                return

            def run():
                react_loop(target, mode, DEFAULT_WORDLIST)
            threading.Thread(target=run, daemon=True).start()

            self.send_response(202)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status":  "accepted",
                "target":  target,
                "mode":    mode,
                "message": "Agent-07 started. Check reports/ for output.",
            }).encode())

    server = HTTPServer(("127.0.0.1", N8N_WEBHOOK_PORT), Handler)
    cprint(C_HEAD, f"\n[WEBHOOK] Agent-07 listening on http://127.0.0.1:{N8N_WEBHOOK_PORT}/webhook/agent07")
    cprint(C_HEAD,  "  POST {\"target\": \"example.com\", \"mode\": \"audit\"}")
    cprint(C_WARN,  "  Note: hash cracking not available via webhook — use CLI\n")
    server.serve_forever()


# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="Agent-07 — Crypto Analysis (hash cracking, TLS audit, cert analysis)"
    )
    parser.add_argument("--target",      help="Target: domain/IP, hash:<val>, cert:<path>, binary:<path>")
    parser.add_argument("--mode",        choices=["fast", "deep", "audit"], default="deep")
    parser.add_argument("--wordlist",    default=DEFAULT_WORDLIST, help="Path to wordlist for hash cracking")
    parser.add_argument("--interactive", action="store_true", help="Interactive mode")
    parser.add_argument("--n8n-server",  action="store_true", help="Start webhook server")
    args = parser.parse_args()

    if args.n8n_server:
        start_webhook_server()
        return

    if args.interactive:
        interactive_mode()
        return

    if not args.target:
        parser.print_help()
        sys.exit(1)

    react_loop(args.target, args.mode, args.wordlist)


if __name__ == "__main__":
    main()
