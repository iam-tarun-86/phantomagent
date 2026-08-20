#!/bin/bash
# ===============================================================================
# PhantomAgent — System Launcher (start.sh)
# Starts Docker Lab, Backend (with sudo for Scapy), and React Dashboard
# ===============================================================================

set -e

# PIDs of background processes
BACKEND_PID=""
FRONTEND_PID=""

# Cleanup: kill backend/frontend + stop Docker lab containers
cleanup() {
    echo -e "\n[SYSTEM] Shutting down PhantomAgent..."
    [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
    [ -n "$FRONTEND_PID" ] && kill "$FRONTEND_PID" 2>/dev/null || true
    echo "[SYSTEM] Stopping Docker Lab containers..."
    docker compose -f docker-compose.lab.yml stop 2>/dev/null || true
    echo "[SYSTEM] ✅ All services stopped cleanly."
    exit 0
}

# Trap Ctrl+C and SIGTERM
trap cleanup SIGINT SIGTERM

# ─────────────────────────────────────────
# 1. Docker Lab Containers
# ─────────────────────────────────────────
echo "[1/4] Checking Docker Lab containers..."
if ! docker compose -f docker-compose.lab.yml ps | grep -q "running"; then
    echo "      Starting Docker Lab containers (kali_attacker & juice_shop)..."
    docker compose -f docker-compose.lab.yml up -d
else
    echo "      Docker Lab containers already UP."
fi

# ─────────────────────────────────────────
# 2. Storage and GNN model
# ─────────────────────────────────────────
echo "[2/4] Initializing storage directories..."
mkdir -p data backend/models
chmod -R 777 data/ 2>/dev/null || true

# Training produces three artefacts and all three are load-bearing: the checkpoint
# carries the normalization statistics, and the two JSON files calibrate the conformal
# and behavioural signals. A stale set means those signals silently degrade to fallbacks.
MODEL_ARTEFACTS=(
    "backend/models/gnn_phantom.pt"
    "backend/models/calibration_scores.json"
    "backend/models/benign_baseline.json"
)
MISSING_ARTEFACT=""
for artefact in "${MODEL_ARTEFACTS[@]}"; do
    if [ ! -f "$artefact" ]; then
        MISSING_ARTEFACT="$artefact"
        break
    fi
done

if [ -n "$MISSING_ARTEFACT" ]; then
    echo "      Missing ${MISSING_ARTEFACT} — training model..."
    [ -f "backend/data/synthetic_graphs.jsonl" ] || \
        PYTHONPATH=. backend/venv/bin/python backend/scripts/generate_dataset.py
    PYTHONPATH=. backend/venv/bin/python backend/scripts/train_gnn.py
else
    echo "      GNN model weights + calibration artefacts found."
fi

# ─────────────────────────────────────────
# 3. Backend (requires sudo for Scapy)
# ─────────────────────────────────────────
echo "[3/4] Starting PhantomAgent Backend (FastAPI + Scapy + GNN + Gemma)..."

# Load .env if present, then forward the PHANTOM_* vars through sudo (which otherwise
# scrubs the environment). Without this, auth config set in your shell is silently lost.
if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    . ./.env
    set +a
fi

sudo PYTHONPATH=/usr/local/lib/python3.12/dist-packages:/home/tarun/.local/lib/python3.12/site-packages:$(pwd) \
    PHANTOM_API_TOKEN="${PHANTOM_API_TOKEN:-}" \
    PHANTOM_USER="${PHANTOM_USER:-admin}" \
    PHANTOM_PASSWORD_HASH="${PHANTOM_PASSWORD_HASH:-}" \
    PHANTOM_HOST="${PHANTOM_HOST:-127.0.0.1}" \
    PHANTOM_PORT="${PHANTOM_PORT:-8000}" \
    PHANTOM_CORS_ORIGINS="${PHANTOM_CORS_ORIGINS:-http://localhost:5173,http://127.0.0.1:5173}" \
    PHANTOM_APPROVAL_TIMEOUT="${PHANTOM_APPROVAL_TIMEOUT:-15}" \
    PHANTOM_DEMO_MODE="${PHANTOM_DEMO_MODE:-true}" \
    backend/venv/bin/python run.py &
BACKEND_PID=$!
echo "      Backend running under PID ${BACKEND_PID} at http://localhost:8000"

# ─────────────────────────────────────────
# 4. Frontend React Dashboard
# ─────────────────────────────────────────
echo "[4/4] Starting React Dashboard Frontend..."
cd frontend && npm run dev &
FRONTEND_PID=$!
cd ..
echo "      Frontend running at http://localhost:5173"

# ─────────────────────────────────────────
echo ""
echo "==============================================================================="
echo "✅ PhantomAgent System Fully Operational!"
echo "   - React Dashboard : http://localhost:5173"
echo "   - Backend API     : http://localhost:8000"
echo "   - Target (Juice)  : http://localhost:3000 (IP: 172.28.0.5)"
echo "   - Attacker (Kali) : Container 'kali_attacker' (IP: 172.28.0.10)"
echo "==============================================================================="
echo "🗡  Run './scripts/demo_attacks.sh' in a 2nd terminal to trigger attacks."
echo "⛔  Press Ctrl+C to stop all services and containers."
echo "==============================================================================="
echo ""

# Keep running, wait for all background processes
wait
