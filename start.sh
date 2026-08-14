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

if [ ! -f "backend/models/gnn_cicids2017.pt" ]; then
    echo "      GNN weights not found — training model..."
    PYTHONPATH=. backend/venv/bin/python backend/scripts/generate_dataset.py
    PYTHONPATH=. backend/venv/bin/python backend/scripts/train_gnn.py
else
    echo "      GNN model weights found."
fi

# ─────────────────────────────────────────
# 3. Backend (requires sudo for Scapy)
# ─────────────────────────────────────────
echo "[3/4] Starting PhantomAgent Backend (FastAPI + Scapy + GNN + Gemma)..."
sudo PYTHONPATH=/usr/local/lib/python3.12/dist-packages:/home/tarun/.local/lib/python3.12/site-packages:$(pwd) \
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
