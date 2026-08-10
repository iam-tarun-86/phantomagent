#!/bin/bash
# ===============================================================================
# PhantomAgent — Master Lab & System Launcher
# Spins up Docker Lab (Kali + Juice Shop), Backend, and React Dashboard
# ===============================================================================

set -e

echo "==============================================================================="
echo "               PHANTOMAGENT — AI INTRUSION DETECTION SYSTEM                    "
echo "==============================================================================="

# 1. Ensure Docker Lab Containers are Running
echo "[1/4] Checking Docker Lab Containers..."
if ! docker compose -f docker-compose.lab.yml ps | grep -q "kali_attacker"; then
    echo "      Starting Docker Lab containers (kali_attacker & juice_shop)..."
    docker compose -f docker-compose.lab.yml up -d
else
    echo "      Docker Lab containers are already UP."
fi

# 2. Ensure Database Directory Exists
echo "[2/4] Initializing Storage Directories..."
mkdir -p data backend/models

# 3. Check GNN Model Weights
if [ ! -f "backend/models/gnn_cicids2017.pt" ]; then
    echo "      GNN model weights not found. Generating dataset and training GNN..."
    PYTHONPATH=. python3 backend/scripts/generate_dataset.py
    PYTHONPATH=. python3 backend/scripts/train_gnn.py
else
    echo "      GNN model weights found at backend/models/gnn_cicids2017.pt."
fi

# 4. Start Backend Server with Scapy Packet Sniffing Capability
echo "[3/4] Starting PhantomAgent Backend Server (FastAPI + Scapy + GNN + Gemma)..."
sudo PYTHONPATH=/home/tarun/.local/lib/python3.12/site-packages:/usr/local/lib/python3.12/dist-packages:. python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
echo "      Backend running under PID ${BACKEND_PID} at http://localhost:8000"

# 5. Start Frontend Dev Server
echo "[4/4] Starting React Dashboard Frontend..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..
echo "      Frontend running at http://localhost:5173"

echo "==============================================================================="
echo "✅ PhantomAgent System Fully Operational!"
echo "   - React Dashboard : http://localhost:5173"
echo "   - Backend API     : http://localhost:8000"
echo "   - Target (Juice)  : http://localhost:3000 (IP: 172.28.0.5)"
echo "   - Attacker (Kali) : Container 'kali_attacker' (IP: 172.28.0.10)"
echo "==============================================================================="
echo "Press Ctrl+C to terminate services."

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" INT TERM

wait
