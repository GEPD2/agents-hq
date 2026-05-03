#!/bin/bash
# ============================================================
#  AGENTS-HQ Stack Setup Script
#  Run as your normal user (v), NOT root
#  Usage: bash setup_stack.sh
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════╗"
echo "║        AGENTS-HQ STACK SETUP          ║"
echo "╚═══════════════════════════════════════╝"
echo -e "${NC}"

BASE="$HOME/Desktop/programming_environment/agents-hq"

# ── 1. Create missing directories ──
echo -e "${YELLOW}[1/8] Creating directory structure...${NC}"
mkdir -p "$BASE/n8n_workflows"
mkdir -p "$BASE/reports/daily"
mkdir -p "$BASE/reports/osint"
mkdir -p "$BASE/reports/redteam"
mkdir -p "$BASE/runtime"
mkdir -p "$BASE/memory"
mkdir -p "$BASE/yara"
mkdir -p "$BASE/agent_06_ghidra/ghidra_projects"
echo -e "${GREEN}    ✓ Directories ready${NC}"

# ── 2. Place nginx config ──
echo -e "${YELLOW}[2/8] Writing nginx ollama proxy config...${NC}"
cat > "$BASE/runtime/nginx-ollama.conf" << 'NGINX'
server {
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
NGINX
echo -e "${GREEN}    ✓ nginx config written${NC}"

# ── 3. Bootstrap API keys file ──
echo -e "${YELLOW}[3/8] Bootstrapping API keys file...${NC}"
if [ ! -f "$BASE/agent_01_osint/.env" ]; then
    cp "$BASE/.env.example" "$BASE/agent_01_osint/.env"
    echo -e "${GREEN}    ✓ Created agent_01_osint/.env from .env.example${NC}"
    echo -e "${YELLOW}    → Edit $BASE/agent_01_osint/.env to add your API keys${NC}"
else
    echo -e "${GREEN}    ✓ agent_01_osint/.env already exists${NC}"
fi

# ── 4. Generate encryption key ──
echo -e "${YELLOW}[4/8] Generating n8n encryption key...${NC}"
ENC_KEY=$(openssl rand -hex 16)
echo -e "${GREEN}    ✓ Key generated: ${ENC_KEY}${NC}"
echo "    → Paste this into docker-compose.yml N8N_ENCRYPTION_KEY"
echo ""
echo -e "${RED}    !! SAVE THIS KEY — if lost, n8n credentials are unrecoverable !!${NC}"
echo "    $ENC_KEY" > "$BASE/runtime/.n8n_key.txt"
echo -e "${YELLOW}    Saved to: $BASE/runtime/.n8n_key.txt (keep this safe)${NC}"

# ── 5. Patch docker-compose.yml with real key ──
echo -e "${YELLOW}[5/8] Patching docker-compose.yml with encryption key...${NC}"
if [ -f "$BASE/docker-compose.yml" ]; then
    sed -i "s/CHANGE_ME_openssl_rand_hex_16/$ENC_KEY/" "$BASE/docker-compose.yml"
    echo -e "${GREEN}    ✓ docker-compose.yml patched${NC}"
else
    echo -e "${RED}    ✗ docker-compose.yml not found at $BASE — copy it there first${NC}"
fi

# ── 6. Verify ollama is running ──
echo -e "${YELLOW}[6/8] Checking ollama service...${NC}"
if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo -e "${GREEN}    ✓ Ollama is running${NC}"
    echo "    Models available:"
    curl -s http://localhost:11434/api/tags | python3 -c "
import json, sys
data = json.load(sys.stdin)
for m in data.get('models', []):
    print(f'      - {m[\"name\"]} ({round(m[\"size\"]/1e9, 1)} GB)')
"
else
    echo -e "${RED}    ✗ Ollama not responding — start it: ollama serve &${NC}"
fi

# ── 7. Build agent image ──
echo ""
echo -e "${YELLOW}[7/8] Building agents-hq Docker image...${NC}"
cd "$BASE"
docker compose build --parallel
echo -e "${GREEN}    ✓ Image built: agents-hq:latest${NC}"

# ── 8. Launch the full stack ──
echo ""
echo -e "${YELLOW}[8/8] Launching AGENTS-HQ stack...${NC}"
docker compose up -d

echo ""
echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                  STACK ONLINE                            ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  n8n UI      →  http://127.0.0.1:5678                   ║"
echo "║  ChromaDB    →  http://127.0.0.1:8000                   ║"
echo "║  Ollama      →  http://127.0.0.1:11434                  ║"
echo "║  Tor SOCKS5  →  127.0.0.1:9050 (for Agent-10)           ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Agent-01 OSINT       →  http://localhost:8765/health   ║"
echo "║  Agent-04 Orchestrator→  http://localhost:8764/health   ║"
echo "║  Agent-05 Red Team    →  http://localhost:8763/health   ║"
echo "║  Agent-06 Ghidra RE   →  http://localhost:8766/health   ║"
echo "║  Agent-07 Crypto      →  http://localhost:8767/health   ║"
echo "║  Agent-08 News Intel  →  http://localhost:8768/health   ║"
echo "║  Agent-09 Market Intel→  http://localhost:8769/health   ║"
echo "║  Agent-10 Dark Web    →  http://localhost:8770/health   ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Status:   docker compose ps                            ║"
echo "║  Logs:     docker compose logs -f [agent-08]           ║"
echo "║  Rebuild:  docker compose build --no-cache             ║"
echo "║  Stop:     docker compose down                         ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${YELLOW}Next step: edit agent_01_osint/.env to add your API keys.${NC}"
