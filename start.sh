#!/bin/bash
# ===============================================================================
# PhantomAgent — System Launcher (start.sh)
# Starts Docker Lab, Backend (with sudo for Scapy), and React Dashboard
# ===============================================================================

set -e

# Function to clean up background processes on exit
cleanup() {
    echo -e "\n[SYSTEM] Stopping backend and frontend..."
    kill $(jobs -p) 2>/dev/null || true
    exit
}

# Trap SIGINT (Ctrl+C) and SIGTERM
trap cleanup SIGINT SIGTERM EXIT

# 1. Ensure Docker Lab containers are running
echo "[SYSTEM] Checking Docker Lab containers..."
if ! docker compose -f docker-compose.lab.yml ps | grep -q "running"; then
    echo "[SYSTEM] Starting Docker Lab containers (kali_attacker & juice_shop)..."
    docker compose -f docker-compose.lab.yml up -d
else
    echo "[SYSTEM] Docker Lab containers already UP."
fi

# 2. Ensure data directories exist
mkdir -p data backend/models

# 3. Check GNN Model Weights
if [ ! -f "backend/models/gnn_cicids2017.pt" ]; then
    echo "[SYSTEM] GNN weights not found. Training GNN model..."
    PYTHONPATH=. backend/venv/bin/python backend/scripts/generate_dataset.py
    PYTHONPATH=. backend/venv/bin/python backend/scripts/train_gnn.py
else
    echo "[SYSTEM] GNN model weights found."
fi

echo "[SYSTEM] Starting backend (with sudo for Scapy packet capture)..."
# Run with sudo + venv python + full PYTHONPATH so scapy can sniff raw packets
sudo PYTHONPATH=/usr/local/lib/python3.12/dist-packages:/home/tarun/.local/lib/python3.12/site-packages:$(pwd) \
    backend/venv/bin/python run.py &
BACKEND_PID=$!
echo "[SYSTEM] Backend running under PID ${BACKEND_PID} at http://localhost:8000"

echo "[SYSTEM] Starting frontend..."
cd frontend && npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "==============================================================================="
echo "✅ PhantomAgent System Fully Operational!"
echo "   - React Dashboard : http://localhost:5173"
echo "   - Backend API     : http://localhost:8000"
echo "   - Target (Juice)  : http://localhost:3000 (IP: 172.28.0.5)"
echo "   - Attacker (Kali) : Container 'kali_attacker' (IP: 172.28.0.10)"
echo "==============================================================================="
echo "Run ./scripts/demo_attacks.sh in a 2nd terminal to trigger attacks."
echo "Press Ctrl+C to terminate services."

# Wait for all background processes to complete
wait
