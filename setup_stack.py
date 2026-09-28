#!/usr/bin/env python3
"""AGENTS-HQ stack control.

Run as your normal user (not root):
    python3 setup_stack.py start     set up directories/certs/keys, build, launch
    python3 setup_stack.py stop      stop the stack, keep every data volume
    python3 setup_stack.py restart   restart services (no rebuild)
    python3 setup_stack.py status    show container status
    python3 setup_stack.py logs      follow logs (optionally for given services)
    python3 setup_stack.py cleanup   remove containers and volumes (research DB is
                                     dumped to reports/backups first)

Python port of setup_stack.sh. On start it creates the directory layout, writes the
nginx Ollama proxy config, bootstraps the API keys file, ensures a per-install n8n
encryption key in a gitignored root .env (never a key committed to the repo), checks
Ollama, then builds and launches the Docker stack. cleanup rotates that key out when it
wipes the n8n volume, so the next start mints a fresh one.
"""

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
NC = "\033[0m"

# The repo root is this script's directory.
BASE = Path(__file__).resolve().parent

# docker compose auto-loads this .env from the project dir; it is gitignored
# (**/.env), so the per-install n8n key never lands in the repo.
ENV_FILE = BASE / ".env"
N8N_KEY_VAR = "N8N_ENCRYPTION_KEY"


def c(color, msg):
    print(f"{color}{msg}{NC}")


def read_env_key():
    if not ENV_FILE.exists():
        return None
    for line in ENV_FILE.read_text().splitlines():
        if line.strip().startswith(N8N_KEY_VAR + "="):
            return line.split("=", 1)[1].strip() or None
    return None


def write_env_key(key):
    lines = ENV_FILE.read_text().splitlines() if ENV_FILE.exists() else []
    out, found = [], False
    for line in lines:
        if line.strip().startswith(N8N_KEY_VAR + "="):
            out.append(f"{N8N_KEY_VAR}={key}")
            found = True
        else:
            out.append(line)
    if not found:
        out.append(f"{N8N_KEY_VAR}={key}")
    ENV_FILE.write_text("\n".join(out) + "\n")


def drop_env_key():
    """Remove the stored n8n key so the next start mints a fresh one."""
    if ENV_FILE.exists():
        kept = [l for l in ENV_FILE.read_text().splitlines()
                if not l.strip().startswith(N8N_KEY_VAR + "=")]
        text = "\n".join(kept).strip()
        if text:
            ENV_FILE.write_text(text + "\n")
        else:
            ENV_FILE.unlink()
    key_file = BASE / "runtime" / ".n8n_key.txt"
    if key_file.exists():
        key_file.unlink()


def banner():
    c(BLUE, "")
    print("AGENTS-HQ STACK SETUP")
    c(NC, "")


def compose(*args, check=True, **kw):
    """Run a docker compose subcommand from the repo root."""
    return subprocess.run(["docker", "compose", *args], cwd=BASE, check=check, **kw)


NGINX_CONF = """server {
    listen 11434;
    location / {
        proxy_pass http://host.docker.internal:11434;
        proxy_http_version 1.1;
        proxy_set_header Connection '';
        chunked_transfer_encoding on;
        proxy_buffering off;
        proxy_cache off;
        proxy_set_header Host localhost;
        proxy_read_timeout 300s;
        proxy_connect_timeout 10s;
        proxy_send_timeout 300s;
    }
}
"""


def step_directories():
    c(YELLOW, "[1/7] Creating directory structure...")
    for rel in (
        "n8n_workflows",
        "reports/daily",
        "reports/osint",
        "reports/redteam",
        "reports/backups",
        "runtime",
        "memory",
        "yara",
        "agent_06_ghidra/ghidra_projects",
    ):
        (BASE / rel).mkdir(parents=True, exist_ok=True)
    c(GREEN, "    Directories ready")


def step_nginx():
    c(YELLOW, "[2/7] Writing nginx ollama proxy config...")
    (BASE / "runtime" / "nginx-ollama.conf").write_text(NGINX_CONF)
    c(GREEN, "    nginx config written")


def step_tls_cert():
    c(YELLOW, "[TLS] Generating self-signed certificate for the HTTPS proxy...")
    certs = BASE / "runtime" / "certs"
    certs.mkdir(parents=True, exist_ok=True)
    cert, key = certs / "cert.pem", certs / "key.pem"
    if cert.exists() and key.exists():
        c(GREEN, "    Certificate already present")
        return
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(cert), "-days", "825",
             "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
            check=True, capture_output=True,
        )
        c(GREEN, f"    Cert written to {certs}")
        c(YELLOW, "    Self-signed: your browser will prompt once at https://127.0.0.1:8443")
    except FileNotFoundError:
        c(RED, "    openssl not found - install it, then re-run; website-tls needs the cert")
    except subprocess.CalledProcessError as e:
        c(RED, f"    openssl failed: {e.stderr.decode(errors='ignore')[:200]}")


def step_geoip():
    c(YELLOW, "[GEO] Fetching keyless IP-to-country dataset for the offline map...")
    data_dir = BASE / "website" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    dest = data_dir / "ip_country.csv"
    if dest.exists() and dest.stat().st_size > 0:
        c(GREEN, "    Dataset already present")
        return
    # CC0 IP-to-country dataset (ip-location-db). Setup-time fetch only; the
    # running app makes no external requests. Try mirrors in order and keep the
    # first that succeeds, so one mirror moving or 404ing does not break setup.
    urls = (
        "https://cdn.jsdelivr.net/npm/@ip-location-db/geo-whois-asn-country/"
        "geo-whois-asn-country-ipv4.csv",
        "https://raw.githubusercontent.com/sapics/ip-location-db/master/"
        "geo-whois-asn-country/geo-whois-asn-country-ipv4.csv",
        "https://raw.githubusercontent.com/sapics/ip-location-db/main/"
        "geo-whois-asn-country/geo-whois-asn-country-ipv4.csv",
    )
    for url in urls:
        host = url.split("/")[2]
        try:
            urllib.request.urlretrieve(url, dest)
            if dest.exists() and dest.stat().st_size > 0:
                c(GREEN, f"    Dataset written to {dest} ({dest.stat().st_size // 1024} KB) via {host}")
                return
        except Exception as e:
            c(YELLOW, f"    Mirror failed ({host}): {e}")
            if dest.exists() and dest.stat().st_size == 0:
                dest.unlink()
    c(RED, "    Could not fetch dataset from any mirror")
    c(YELLOW, "    Geo map will fall back to cached geo until this file is present")


def step_env():
    c(YELLOW, "[3/7] Bootstrapping API keys file...")
    env_path = BASE / "agent_01_osint" / ".env"
    if not env_path.exists():
        example = (BASE / ".env.example").read_text()
        env_path.write_text(example)
        c(GREEN, "    Created agent_01_osint/.env from .env.example")
        c(YELLOW, f"    Edit {env_path} to add your API keys")
    else:
        c(GREEN, "    agent_01_osint/.env already exists")


def step_key():
    c(YELLOW, "[4/7] Ensuring per-install n8n encryption key...")
    if read_env_key():
        c(GREEN, "    Key already present in .env, reusing it (stable across restarts)")
        return
    enc_key = secrets.token_hex(16)
    write_env_key(enc_key)
    key_file = BASE / "runtime" / ".n8n_key.txt"
    key_file.write_text(f"    {enc_key}\n")
    c(GREEN, "    New per-install key written to .env (gitignored, unique to this install)")
    c(RED, "    SAVE THIS KEY. If lost, n8n credentials are unrecoverable.")
    c(YELLOW, f"    Backup copy at: {key_file} (keep this safe; not printed here)")


def step_check_ollama():
    c(YELLOW, "[5/7] Checking ollama service...")
    try:
        with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=5) as resp:
            data = json.load(resp)
        c(GREEN, "    Ollama is running")
        print("    Models available:")
        for m in data.get("models", []):
            size_gb = round(m.get("size", 0) / 1e9, 1)
            print(f"      - {m['name']} ({size_gb} GB)")
    except Exception:
        c(RED, "    Ollama not responding - start it: ollama serve &")


def step_build():
    print("")
    c(YELLOW, "[6/7] Building agents-hq Docker image...")
    compose("build", "--parallel")
    c(GREEN, "    Image built: agents-hq:latest")


def step_launch():
    print("")
    c(YELLOW, "[7/7] Launching AGENTS-HQ stack...")
    compose("up", "-d")


ONLINE_NOTICE = """
STACK ONLINE

  Control panel ->  https://127.0.0.1:8443  (TLS, self-signed)
                ->  http://127.0.0.1:8080   (loopback, direct)
  n8n UI       ->  http://127.0.0.1:5678
  ChromaDB     ->  http://127.0.0.1:8000
  Ollama       ->  http://127.0.0.1:11434
  Tor SOCKS5   ->  127.0.0.1:9050 (for Agent-10)

  Agent-01 OSINT        ->  http://localhost:8765/health
  Agent-04 Orchestrator ->  http://localhost:8764/health
  Agent-05 Red Team     ->  http://localhost:8763/health
  Agent-06 Ghidra RE    ->  http://localhost:8766/health
  Agent-07 Crypto       ->  http://localhost:8767/health
  Agent-08 News Intel   ->  http://localhost:8768/health
  Agent-09 Market Intel ->  http://localhost:8769/health
  Agent-10 Dark Web     ->  http://localhost:8770/health

  Status:   python3 setup_stack.py status
  Logs:     python3 setup_stack.py logs [agent-08]
  Stop:     python3 setup_stack.py stop
  Cleanup:  python3 setup_stack.py cleanup   (dumps the research DB, then wipes volumes)
  Rebuild:  docker compose build --no-cache
"""


def cmd_start(args):
    banner()
    step_directories()
    step_nginx()
    step_tls_cert()
    step_geoip()
    step_env()
    step_key()
    step_check_ollama()
    try:
        step_build()
        step_launch()
    except FileNotFoundError:
        c(RED, "    docker not found - install Docker, then re-run this script")
        return 1
    except subprocess.CalledProcessError as e:
        c(RED, f"    docker compose failed (exit {e.returncode})")
        return e.returncode
    c(GREEN, ONLINE_NOTICE)
    c(YELLOW, "Next step: edit agent_01_osint/.env to add your API keys.")
    return 0


def cmd_stop(args):
    c(YELLOW, "Stopping AGENTS-HQ stack (containers down, data volumes kept)...")
    try:
        compose("down")
    except FileNotFoundError:
        c(RED, "    docker not found")
        return 1
    except subprocess.CalledProcessError as e:
        return e.returncode
    c(GREEN, "    Stack stopped. Research data in mysql_data and n8n_data is preserved.")
    c(YELLOW, "    Start again with: python3 setup_stack.py start")
    return 0


def cmd_restart(args):
    target = args.services or ["all services"]
    c(YELLOW, f"Restarting AGENTS-HQ ({' '.join(target)})...")
    try:
        compose("restart", *args.services)
    except FileNotFoundError:
        c(RED, "    docker not found")
        return 1
    except subprocess.CalledProcessError as e:
        return e.returncode
    c(GREEN, "    Restarted.")
    return 0


def cmd_status(args):
    try:
        compose("ps")
    except FileNotFoundError:
        c(RED, "    docker not found")
        return 1
    except subprocess.CalledProcessError as e:
        return e.returncode
    return 0


def cmd_logs(args):
    try:
        compose("logs", "-f", *args.services, check=False)
    except FileNotFoundError:
        c(RED, "    docker not found")
        return 1
    except KeyboardInterrupt:
        pass
    return 0


def _mysql_ready(user, pw, retries=30, delay=2):
    for _ in range(retries):
        r = compose("exec", "-T", "mysql", "mysqladmin", "ping",
                    "-h", "localhost", f"-u{user}", f"-p{pw}",
                    check=False, capture_output=True)
        if r.returncode == 0:
            return True
        time.sleep(delay)
    return False


def backup_mysql():
    """Dump the research database to a host file that survives volume removal.

    Returns the backup path on success, or None if it could not be produced.
    """
    backups = BASE / "reports" / "backups"
    backups.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = backups / f"mysql_agents_hq_{stamp}.sql"
    db = os.environ.get("MYSQL_DATABASE", "agents_hq")
    user = os.environ.get("MYSQL_USER", "agents")
    pw = os.environ.get("MYSQL_PASSWORD", "agents_hq")

    c(YELLOW, "    Making sure MySQL is up so the research data can be dumped...")
    try:
        compose("up", "-d", "mysql", capture_output=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        c(RED, f"    Could not start MySQL for backup: {e}")
        return None
    if not _mysql_ready(user, pw):
        c(RED, "    MySQL did not become ready; skipping backup")
        return None

    c(YELLOW, f"    Dumping database '{db}' to {dest} ...")
    try:
        with open(dest, "wb") as fh:
            compose("exec", "-T", "mysql",
                    "mysqldump", f"-u{user}", f"-p{pw}", "--databases", db,
                    check=True, stdout=fh, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        err = (e.stderr or b"").decode(errors="ignore")[:200]
        c(RED, f"    mysqldump failed: {err}")
        return None
    if dest.stat().st_size == 0:
        c(RED, "    Backup file is empty; treating as failed")
        return None
    c(GREEN, f"    Research data backed up: {dest} ({dest.stat().st_size // 1024} KB)")
    return dest


def cmd_cleanup(args):
    c(RED, "CLEANUP removes AGENTS-HQ containers, networks, and named volumes")
    c(RED, "        (mysql_data = your research DB, n8n_data = n8n credentials/executions).")
    c(YELLOW, "Host folders (reports/, runtime/, n8n_workflows/, memory/) are NOT touched.")

    backup = None
    if not args.no_backup:
        c(YELLOW, "\nBacking up the research database before removing volumes...")
        backup = backup_mysql()
        if backup is None and not args.force:
            c(RED, "\nBackup did not succeed. Aborting so no research data is lost.")
            c(YELLOW, "    Re-run with --force to wipe anyway, or --no-backup to skip the dump.")
            return 1

    if not args.yes:
        c(YELLOW, "\nType 'wipe' to remove the containers and volumes: ")
        try:
            answer = input().strip()
        except EOFError:
            answer = ""
        if answer != "wipe":
            c(GREEN, "    Cancelled. Nothing was removed.")
            return 0

    try:
        compose("down", "-v", "--remove-orphans")
    except FileNotFoundError:
        c(RED, "    docker not found")
        return 1
    except subprocess.CalledProcessError as e:
        return e.returncode

    drop_env_key()
    c(GREEN, "\n    Stack removed and volumes wiped.")
    c(YELLOW, "    n8n key rotated out (.env cleared); the next start mints a fresh one.")
    if backup:
        c(GREEN, f"    Research backup kept at: {backup}")
        c(YELLOW, "    Restore into a fresh stack with:")
        c(NC, "      python3 setup_stack.py start")
        c(NC, f"      docker compose exec -T mysql sh -c 'exec mysql -uroot -pagents_root_hq' < {backup}")
    return 0


HANDLERS = {
    "start": cmd_start,
    "stop": cmd_stop,
    "restart": cmd_restart,
    "status": cmd_status,
    "logs": cmd_logs,
    "cleanup": cmd_cleanup,
}


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="setup_stack.py", description="AGENTS-HQ stack control")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("start", help="set up and launch the full stack")
    sub.add_parser("stop", help="stop the stack, keep all data volumes")

    p_restart = sub.add_parser("restart", help="restart services (no rebuild)")
    p_restart.add_argument("services", nargs="*", help="specific services, or empty for all")

    sub.add_parser("status", help="show container status")

    p_logs = sub.add_parser("logs", help="follow logs (optionally for given services)")
    p_logs.add_argument("services", nargs="*", help="specific services, or empty for all")

    p_clean = sub.add_parser(
        "cleanup", help="remove containers and volumes (research DB is dumped first)")
    p_clean.add_argument("--yes", action="store_true", help="skip the typed confirmation")
    p_clean.add_argument("--no-backup", action="store_true", help="do not dump the research DB first")
    p_clean.add_argument("--force", action="store_true", help="wipe even if the backup fails")

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    return HANDLERS[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
