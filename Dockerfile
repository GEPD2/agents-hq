# ============================================================
#  AGENTS-HQ — Shared Agent Image
#  Base: Python 3.12 slim
#  Tools: nmap, openssl, john, hashcat, Java, binutils, ssdeep
#  Python: requests, pefile
#  Network: host (see docker-compose.yml) — agents connect to
#           Ollama (localhost:11434) and ChromaDB (localhost:8000)
#           directly through the host network stack
# ============================================================

FROM python:3.12-slim

LABEL org.opencontainers.image.title="AGENTS-HQ"
LABEL org.opencontainers.image.description="Autonomous security intelligence platform"

# ── System packages ───────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network recon — Agent-01, 02
    nmap \
    dnsutils \
    netcat-openbsd \
    whois \
    # Crypto / TLS / hash cracking — Agent-07
    openssl \
    john \
    hashcat \
    # Binary analysis — Agent-06
    binutils \
    file \
    libmagic1 \
    libfuzzy-dev \
    ssdeep \
    # Java (headless) — Agent-06 Ghidra headless analyzer
    default-jre-headless \
    # General utilities
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Python packages ───────────────────────────────────────────
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# ── Project layout ────────────────────────────────────────────
WORKDIR /agents-hq
COPY . /agents-hq/

RUN mkdir -p \
    /agents-hq/reports \
    /agents-hq/yara \
    /agents-hq/agent_06_ghidra/ghidra_projects

# ── Runtime env ──────────────────────────────────────────────
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Overridden per-service in docker-compose.yml
CMD ["python3", "--version"]
