import asyncio
import sys
sys.path.insert(0, './backend')

# Import the state module directly, not main
from backend.main import state

async def inject_test():
    print(f"[TEST] Clients in state: {len(state.clients)}")
    print(f"[TEST] Threats in state: {len(state.threats)}")
    
    event = {
        "source": "WATCHER",
        "type": "BRUTE_FORCE",
        "severity": 9,
        "source_ip": "185.220.101.47",
        "raw_log": "Failed password for root from 185.220.101.47 port 22 ssh2",
        "timestamp": "2026-06-26T00:00:00",
        "message": "SSH brute force detected"
    }
    
    print("[TEST] Injecting event...")
    await state.process_event(event)
    print(f"[TEST] Done. Threats: {len(state.threats)}, Logs: {len(state.logs)}")

asyncio.run(inject_test())