#!/bin/bash

# Function to clean up background processes on exit
cleanup() {
    echo -e "\n[SYSTEM] Stopping backend and frontend..."
    kill $(jobs -p) 2>/dev/null
    exit
}

# Trap SIGINT (Ctrl+C) and SIGTERM
trap cleanup SIGINT SIGTERM EXIT

echo "[SYSTEM] Starting backend..."
backend/venv/bin/python run.py &

echo "[SYSTEM] Starting frontend..."
cd frontend && npm run dev &

# Wait for all background processes to complete
wait
