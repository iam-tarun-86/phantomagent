#!/usr/bin/env python3
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from backend.main import app
import uvicorn
from backend.config import API_HOST, API_PORT

if __name__ == "__main__":
    print("[RUNNER] Starting PhantomAgent Backend...")
    print(f"[RUNNER] API: http://{API_HOST}:{API_PORT}")
    print(f"[RUNNER] WebSocket: ws://{API_HOST}:{API_PORT}/ws")
    uvicorn.run(app, host=API_HOST, port=API_PORT)